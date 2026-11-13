// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The admitter's side: who may admit whom, and the joiner's first record.
//!
//! The rules (design-records-v3 section 7, design-small-device 15, the
//! owner's decisions of 2026-11-11):
//!
//! - The joiner's device ID is its key's hash. An ID that a kept record
//!   names, a removed device's included, is taken while that record is
//!   kept: the device comes back only by a new admission, never by an old
//!   record.
//! - A root admits anyone. An admin with `admit` admits any device with
//!   base rights (read and send, secrets only when its own device has
//!   them), an ordinary leaf included; a guarded leaf only a root admits.
//! - An admin key goes into the record only with its proof of possession,
//!   and only in a record a root signs. Its powers are one of the core's
//!   three sets ([`AdminKind::grants`]); no client sets the bits itself.
//! - Where a key is stored is never taken on the device's word: a store
//!   counts as proven only with evidence the admitter checked; anything
//!   else is a file.

use crate::records::body::{
    AdminKind, CAP_HUB, Device, POWER_ADMIT, RIGHT_HUB, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_LEAF, STORE_FILE,
    STORE_PROVEN,
};
use crate::records::eval::DeviceState;
use crate::records::{Key, KeyHash, State};

use super::info::Info;
use super::invitation::Profile;

/// Why an admitter does not admit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The joiner's device ID is taken (a removed device's too).
    Taken,
    /// This device may not admit: not a root, no admin key with `admit`,
    /// frozen or removed.
    NotAdmitter,
    /// Only the root admits a guarded leaf.
    GuardedNeedsRoot,
    /// The joiner's key is not a P-256 key on the curve.
    BadKey,
    /// The joiner asks for more than its invitation's profile: another
    /// role, or a hub where the profile gives none.
    AsksMore,
}

impl Refusal {
    /// A sentence for the user.
    pub fn message(self) -> &'static str {
        match self {
            Refusal::Taken => {
                "this device's ID is taken: a removed device comes back only after a reset, with a new key"
            }
            Refusal::NotAdmitter => "this device may not admit devices to the group",
            Refusal::GuardedNeedsRoot => "only the group's main device admits a lock or another guarded device",
            Refusal::BadKey => "the joining device's key is damaged",
            Refusal::AsksMore => "the joining device asks for more than its invitation allows",
        }
    }
}

/// Who signs the joiner's record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Signer {
    /// The current root key.
    Root,
    /// An admin key: the admitter's own device's.
    Admin,
}

/// What the admitter checked about the joiner beyond its Info.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Checked {
    /// The admin key's proof over this session verified
    /// (`crate::join::verify_admin_pop`).
    pub admin_pop: bool,
    /// Key evidence the admitter verified itself, as the record's `proof`
    /// (1 android-tee, 2 android-strongbox, 3 tpm); None counts as a file.
    pub proof: Option<u64>,
}

/// What the user chose on the decision screen.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Choice {
    /// The rights a root gives (an admin's are fixed: read and send, and
    /// secrets when its own device has them).
    pub rights: u64,
    /// The admin set, when a root makes the joiner an admin and it offered
    /// a proven admin key.
    pub admin: Option<AdminKind>,
    /// A guarded leaf (a lock, a door): the firmware says so, or the root.
    pub guarded: bool,
}

/// Whether the device with member key `admitter` may sign a first record as
/// `signer`: a root signs as the root; an admin's device is in the records,
/// not frozen, with an admin key that has `admit`. Nobody admits while the
/// group is stopped (`State::stopped`).
pub fn may_admit(state: &State, admitter: &KeyHash, signer: Signer, root_key: &KeyHash) -> bool {
    if state.stopped() {
        return false;
    }
    match signer {
        Signer::Root => state.is_root(root_key) && !state.two_histories(root_key),
        Signer::Admin => state.device_by_key(admitter).is_some_and(|d| {
            !d.frozen
                && d.powers & POWER_ADMIT != 0
                && d.admin.as_ref().is_some_and(|a| !state.revoked.contains(a) && !state.two_histories(a))
        }),
    }
}

/// The joiner's first record, as the admitter signs it; or why not.
/// `own` is the admitter's own device (an admin's is needed: whether it may
/// admit, whether it has secrets). `profile` is that of the invitation the
/// joiner came by: the record never gives more than it (A-42), and a
/// guarded profile makes a guarded leaf, which only the root admits.
#[allow(clippy::too_many_arguments, reason = "each is one input of the admission")]
pub fn joiner_record(
    state: &State,
    signer: Signer,
    own: Option<&DeviceState>,
    joiner_key: &[u8; 65],
    info: &Info,
    profile: &Profile,
    checked: Checked,
    choice: Choice,
) -> Result<Device, Refusal> {
    let may = match signer {
        Signer::Root => state.roots.last().is_some_and(|r| may_admit(state, r, Signer::Root, r)),
        Signer::Admin => own.is_some_and(|o| may_admit(state, &o.key.hash(), Signer::Admin, &KeyHash([0; 32]))),
    };
    if !may {
        return Err(Refusal::NotAdmitter);
    }
    let key = Key::es256(joiner_key.to_vec());
    if key.check().is_err() {
        return Err(Refusal::BadKey);
    }
    if state.id_taken(&key.device_id()) || state.revoked.contains(&key.hash()) {
        return Err(Refusal::Taken);
    }
    // An admin key it offers is new too: not its member key, not removed,
    // not named by a record the member keeps.
    if let Some(a) = info.admin_key() {
        let h = a.hash();
        if a.public() == key.public()
            || state.revoked.contains(&h)
            || state.id_taken(&a.device_id())
            || state.roots.contains(&h)
            || state.recovery == h
            || state.devices.iter().any(|d| d.admin == Some(h) || d.key.hash() == h)
        {
            return Err(Refusal::Taken);
        }
    }
    if info.role != profile.role || (info.caps & CAP_HUB != 0 && profile.rights & RIGHT_HUB == 0) {
        return Err(Refusal::AsksMore);
    }
    let guarded = (choice.guarded || profile.guarded) && info.role == ROLE_LEAF;
    if guarded && signer != Signer::Root {
        return Err(Refusal::GuardedNeedsRoot);
    }
    let mut d = Device::new(key, &info.name, info.role);
    d.os = info.os;
    d.caps = info.caps;
    d.guarded = guarded;
    match (checked.proof, info.role) {
        (Some(p), r) if r != ROLE_LEAF && (1..=3).contains(&p) => {
            d.store = STORE_PROVEN;
            d.proof = p;
        }
        _ => d.store = STORE_FILE,
    }
    match signer {
        Signer::Admin => {
            let secrets = own.is_some_and(|o| o.rights & RIGHT_SECRETS != 0);
            d.rights = (RIGHT_READ | RIGHT_SEND | if secrets { RIGHT_SECRETS } else { 0 }) & profile.rights;
        }
        Signer::Root => {
            d.rights = choice.rights & profile.rights;
            if let (Some(kind), Some(admin), true) = (choice.admin, info.admin_key(), checked.admin_pop) {
                let (powers, commands) = kind.grants();
                d.admin = Some(admin);
                d.powers = powers;
                d.commands = commands;
            }
        }
    }
    Ok(d)
}
