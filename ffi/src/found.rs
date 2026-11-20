// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A phone makes a new group on the records of 0.6 (`cbb_group_new` with
//! `dir`): the root key and the member key stay in the app and sign
//! through its callback; the core makes the recovery secret, from which
//! the recovery key's two halves come, writes the phone's record under the
//! root and keeps the set in the app's folder, where `cbb_member_start`
//! then reads it. The same step as a computer's (`cbb_member::founding`),
//! with the keys the app holds in place of ones in files. The recovery
//! sheet goes to the app once; the core keeps it nowhere.

use std::path::PathBuf;

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::records::body::{Device, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_PHONE, STORE_FILE, STORE_HARDWARE};
use cbb_core::records::{Key, Kind, RecordSet};
use cbb_core::sheet;
use cbb_member::roster::id_text;
use serde::{Deserialize, Serialize};

use crate::join::{AppKey, SignFn, answer, wall_ms};

/// What `cbb_group_new` takes for a group of 0.6.
#[derive(Deserialize)]
struct Args {
    /// The app's folder, where the set is kept.
    dir: String,
    name: String,
    os: String,
    /// hardware or file: where the member key is, as the person reads it.
    store: String,
    #[serde(with = "certs::b64")]
    root_public: Vec<u8>,
    /// The member key's point.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
}

/// The recovery sheet: what the person writes down or prints, once.
#[derive(Serialize)]
struct Sheet {
    /// The QR code's text, CBBR1….
    qr: String,
    /// The sheet's 4 lines of 4 groups of 4 characters.
    text: Vec<String>,
    /// The QR code's modules, a row of '1' and '0' each, for an app that
    /// draws it from them (Aurora).
    modules: Vec<String>,
}

#[derive(Serialize)]
struct Made {
    group: String,
    device: String,
    recovery: Sheet,
}

/// Whether a group request names the app's folder, as a request of 0.6
/// does.
pub(crate) fn on_06(request: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Dir {
        #[serde(default)]
        dir: String,
    }
    serde_json::from_slice::<Dir>(request).is_ok_and(|d| !d.dir.is_empty())
}

/// Makes the group and answers its IDs and the recovery sheet.
pub fn new_group(request: &[u8], sign: SignFn, ctx: usize) -> Vec<u8> {
    answer((|| -> Result<Made> {
        let a: Args = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the group request does not decode: {e}")))?;
        let store = match a.store.as_str() {
            "hardware" => STORE_HARDWARE,
            "file" => STORE_FILE,
            s => return Err(Error::msg(format!("the key store is hardware or file, not {s:?}"))),
        };
        let name = a.name.trim();
        if name.is_empty() {
            return Err(Error::msg("this phone needs a name for its group"));
        }
        let dir = PathBuf::from(&a.dir);
        if dir.join(cbb_member::set::FILE_NAME).exists() {
            return Err(Error::msg("this phone is already in a group"));
        }
        std::fs::create_dir_all(&dir).map_err(|e| Error::msg(format!("cannot make the app's folder: {e}")))?;
        let root = AppKey { public: a.root_public, sign, ctx };
        let (secret, recovery) = cbb_member::founding::new_recovery()?;
        let mut set = RecordSet::new(Key::es256(root.public.clone()), recovery);
        let member = Key::es256(a.public);
        let device = id_text(&member.device_id());
        let mut d = Device::new(member, name, ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
        d.os = cbb_core::format::print::os_number(&a.os);
        d.store = store;
        d.holds_root = true;
        let st = set.state();
        let now = wall_ms().max(0).unsigned_abs();
        set.write_record(&st, &root, Kind::device(d), now)
            .map_err(|e| Error::msg(format!("cannot write this phone's record: {e}")))?;
        let local = cbb_member::set::local_key(&dir)?;
        cbb_member::set::save(&dir, &set, &local)?;
        let group = set.state().group;
        let qr = sheet::qr(&secret, &group);
        let modules = crate::join::modules(&qr)?;
        Ok(Made {
            group: id_text(&group),
            device,
            recovery: Sheet { qr, text: sheet::text(&secret).lines().map(str::to_string).collect(), modules },
        })
    })())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use cbb_core::identity::{ExternalKey, FileKey};

    use super::*;

    unsafe extern "C" fn no_sign(_: *mut core::ffi::c_void, _: *const u8, _: *mut u8, _: *mut usize) -> i32 {
        1
    }

    unsafe extern "C" fn sign_with(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, n: *mut usize) -> i32 {
        // SAFETY: the test passes a FileKey as ctx and the core 32 bytes at
        // digest and room for a DER signature at sig.
        let (k, d) = unsafe { (&*(ctx as *const FileKey), &*(digest as *const [u8; 32])) };
        let s = k.sign_digest(d).unwrap();
        // SAFETY: as above.
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), sig, s.len());
            *n = s.len();
        }
        0
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cbb-ffi-found-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_phone_makes_a_group_it_is_the_root_of_and_a_sheet_that_reads() {
        let d = dir("made");
        let root = FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap();
        let member = FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap();
        let req = serde_json::json!({
            "dir": d.to_string_lossy(), "name": "iPhone", "os": "ios", "store": "hardware",
            "root_public": certs::b64::encode(&root.public()), "public": certs::b64::encode(&member.public()),
        });
        let req = serde_json::to_vec(&req).unwrap();
        assert!(on_06(&req));
        let got: serde_json::Value =
            serde_json::from_slice(&new_group(&req, sign_with, &root as *const FileKey as usize)).unwrap();
        let ok = &got["ok"];
        let set = cbb_member::set::load(&d, &cbb_member::set::local_key(&d).unwrap()).unwrap().unwrap();
        let st = set.state();
        assert_eq!(ok["group"], id_text(&st.group));
        let me = st.devices.first().expect("the phone's record");
        assert_eq!(st.devices.len(), 1);
        assert_eq!((me.name.as_str(), me.role, me.store), ("iPhone", ROLE_PHONE, STORE_HARDWARE));
        assert_eq!(st.root_device, Some(me.id));
        assert_eq!(ok["device"], id_text(&me.key.device_id()));
        assert_eq!(st.roots.last(), Some(&Key::es256(root.public()).hash()));
        let text: Vec<String> = serde_json::from_value(ok["recovery"]["text"].clone()).unwrap();
        assert_eq!(text.len(), 4);
        let read = sheet::read(&text.join("\n")).unwrap();
        sheet::check(&read, &st.group, set.recovery()).unwrap();
        assert!(sheet::read(ok["recovery"]["qr"].as_str().unwrap()).is_ok());
        assert!(!ok["recovery"]["modules"].as_array().unwrap().is_empty());
        // Only once.
        let again: serde_json::Value =
            serde_json::from_slice(&new_group(&req, sign_with, &root as *const FileKey as usize)).unwrap();
        assert!(again["error"]["message"].as_str().unwrap().contains("already in a group"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_root_key_that_does_not_sign_keeps_nothing() {
        let d = dir("nosign");
        let member = FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap();
        let req = serde_json::to_vec(&serde_json::json!({
            "dir": d.to_string_lossy(), "name": "iPhone", "os": "ios", "store": "file",
            "root_public": certs::b64::encode(&member.public()), "public": certs::b64::encode(&member.public()),
        }))
        .unwrap();
        let got: serde_json::Value = serde_json::from_slice(&new_group(&req, no_sign, 0)).unwrap();
        assert!(got["error"]["message"].as_str().unwrap().contains("cannot write"), "{got}");
        assert!(!d.join(cbb_member::set::FILE_NAME).exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
