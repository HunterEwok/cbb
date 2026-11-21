// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A new group on the records of 0.6, made on a computer (cbb new): the
//! device's root key (`own`), a recovery secret from which the recovery
//! key's two halves come (`records::pq::recovery_keys`), the group's
//! first record set with this device's record under the root, and the
//! recovery sheet that the person keeps on paper (`cbb_core::sheet`). The
//! secret is shown once and kept nowhere.

use std::path::Path;

use cbb_core::records::body::{Device, ROLE_MEMBER, STORE_FILE, STORE_HARDWARE, STORE_ROOTLESS};
use cbb_core::records::key::ALG_SLH_DSA;
use cbb_core::records::{Key, Kind, RecordSet, Recovery, pq};
use cbb_core::secret::Zeroizing;
use cbb_core::sheet;
use p256::elliptic_curve::sec1::ToSec1Point as _;

use crate::error::{Error, Result};
use crate::own::{Own, Which};

/// What a new group gives back: its set, and the recovery sheet's text
/// and QR code's text, which only the person keeps.
pub struct Founded {
    pub set: RecordSet,
    pub sheet: Zeroizing<String>,
    pub qr: Zeroizing<String>,
    /// The root key is in this computer's hardware, not in a file.
    pub root_held: bool,
    /// Why the keys are in files although the hardware was asked, if it
    /// said.
    pub key_problem: String,
}

/// This device as its record in the new group names it.
pub struct Me<'a> {
    pub name: &'a str,
    pub os: u64,
    pub caps: u64,
}

/// Makes a new group in dir, this device its root; an error when the
/// device is in a group already.
pub fn found(dir: &Path, me: &Me<'_>, now_ms: u64) -> Result<Founded> {
    // The hardware is asked once more only after it made a key: a helper
    // that fails or hangs costs its wait once, not for every key.
    let problem = std::sync::Mutex::new(None::<String>);
    let hardware = || {
        if problem.lock().unwrap().is_some() {
            return None;
        }
        let (k, why) = crate::keys::new_device_key();
        if k.is_none() {
            *problem.lock().unwrap() = Some(why);
        }
        k
    };
    let mut f = found_with(dir, me, now_ms, &hardware)?;
    f.key_problem = problem.into_inner().unwrap().unwrap_or_default();
    Ok(f)
}

/// found, with the hardware's key maker given.
pub fn found_with(
    dir: &Path,
    me: &Me<'_>,
    now_ms: u64,
    hardware: &dyn Fn() -> Option<std::sync::Arc<dyn cbb_core::identity::ExternalKey>>,
) -> Result<Founded> {
    if dir.join(crate::set::FILE_NAME).exists() || dir.join(crate::identity::FILE_NAME).exists() {
        return Err(Error::msg("this device is already in a group; cbb status shows it"));
    }
    let name = me.name.trim();
    if name.is_empty() {
        return Err(Error::msg("this device needs a name for its group"));
    }
    let mut own = Own::load_with(dir, &crate::keys::open, hardware)?;
    let root = own.make_with(dir, Which::Root, hardware)?;
    let secret = Zeroizing::new(cbb_core::certs::random_bytes::<32>());
    let (k1, k2) = pq::recovery_keys(&secret).map_err(|e| e.context("cannot make the recovery key"))?;
    let k1 = Key::es256(k1.public_key().to_sec1_point(false).as_bytes().to_vec());
    let recovery = Recovery::new(k1, Key::new(ALG_SLH_DSA, k2.public()))
        .ok_or_else(|| Error::msg("the recovery key's halves are not the keys a recovery key has"))?;
    let mut set = RecordSet::new(Key::es256(root.public()), recovery);
    let mut d = Device::new(own.member_key(), name, ROLE_MEMBER);
    d.rights = crate::admitting::rights_of(ROLE_MEMBER, me.caps);
    d.caps = me.caps;
    d.os = me.os;
    d.holds_root = true;
    // Where its member key is: unproven, as a person reads it.
    d.store = if crate::rootless::is() {
        STORE_ROOTLESS
    } else if own.member.held().is_some() {
        STORE_HARDWARE
    } else {
        STORE_FILE
    };
    let st = set.state();
    set.write_record(&st, &*root, Kind::device(d), now_ms)
        .map_err(|e| Error::msg(format!("cannot write this device's record: {e}")))?;
    // A root whose key is in a file starts the group at the key level
    // files, which its own key meets; cbb keys raises it.
    if root.held().is_none() {
        let st = set.state();
        let mut settings = st.settings.clone();
        settings.key_level = cbb_core::records::body::LEVEL_FILES;
        set.write_record(&st, &*root, Kind::settings(settings), now_ms)
            .map_err(|e| Error::msg(format!("cannot write the group's settings: {e}")))?;
    }
    let local = crate::set::local_key(dir)?;
    crate::set::save(dir, &set, &local)?;
    let group = set.state().group;
    Ok(Founded {
        sheet: Zeroizing::new(sheet::text(&secret)),
        qr: Zeroizing::new(sheet::qr(&secret, &group)),
        root_held: root.held().is_some(),
        key_problem: String::new(),
        set,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_group_has_this_device_as_its_root_and_a_sheet_that_reads() {
        let dir = std::env::temp_dir().join(format!("cbb-found-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = Me { name: "desk", os: 1, caps: cbb_core::records::body::CAP_ADMIN };
        let f = found_with(&dir, &me, 1_700_000_000_000, &|| None).unwrap();
        let st = f.set.state();
        let own = Own::load_with(&dir, &crate::keys::open, &|| None).unwrap();
        assert_eq!(st.root_device, Some(own.device()));
        assert_eq!(st.devices.len(), 1);
        assert_eq!(st.devices[0].name, "desk");
        // The root key signs: the device can write the group's records.
        assert!(crate::writers::signer(&own, &st).is_some());
        // The sheet reads back, and checks against the group's recovery key.
        let read = sheet::read(&f.sheet).unwrap();
        sheet::check(&read, &st.group, f.set.recovery()).unwrap();
        assert!(sheet::read(&f.qr).is_ok());
        // Kept, and only once.
        let local = crate::set::local_key(&dir).unwrap();
        assert_eq!(crate::set::load(&dir, &local).unwrap().unwrap().digest(), f.set.digest());
        let again = found_with(&dir, &me, 1_700_000_000_000, &|| None).err().unwrap();
        assert!(again.message().contains("already in a group"));
    }
}
