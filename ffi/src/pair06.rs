// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A phone admits a device on the records of 0.6 (format section 11.1):
//! once a pairing session is approved (at home by both persons' "they
//! match", by an invitation by its secret), the app's root or admin key
//! signs the joiner's first record as the core's admission rules give it
//! (`join::decide::joiner_record`), and the Welcome goes with the set that
//! holds it. The same step as a computer's (`cbb_member::admitting`), with
//! the key the app holds in place of one in a file.

use cbb_core::error::{Error, Result};
use cbb_core::identity::ExternalKey;
use cbb_core::join::decide::{self, Checked, Choice, Signer};
use cbb_core::join::info::Info;
use cbb_core::join::invitation::Profile;
use cbb_core::join::session::MemberSession;
use cbb_core::join::welcome::Welcome;
use cbb_core::records::body::{Kind, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_LEAF, ROLE_WATCH};
use cbb_core::records::{Key, RecordSet};

/// What a device admitted at home may get: a member or a phone reads,
/// sends and takes secrets; a watch only reads, through its phone; a leaf
/// joins at home by its own profile, never by this one.
pub(crate) fn home_profile(role: u64) -> Profile {
    let rights = if role == ROLE_WATCH { RIGHT_READ } else { RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS };
    Profile { role, rights, home_only: true, guarded: false }
}

/// Who `key` signs as in `set`: the current root, or an admin.
fn signer_of(set: &RecordSet, key: &dyn ExternalKey) -> Signer {
    let hash = Key::es256(key.public()).hash();
    if set.state().roots.last() == Some(&hash) { Signer::Root } else { Signer::Admin }
}

/// Writes the joiner's first record into `set` with `key` and gives the
/// frames of message 67 and its parts. `own` is the admitting device's
/// member key: an admin's own device must be one that may admit. The
/// profile bounds what the record gives; at home it is [`home_profile`]
/// of the role the joiner asks for, and a leaf is refused.
#[allow(clippy::too_many_arguments, reason = "each is one input of the admission")]
pub(crate) fn admit(
    set: &mut RecordSet,
    key: &dyn ExternalKey,
    own: &[u8],
    joiner: &[u8; 65],
    info: &Info,
    profile: &Profile,
    session: &mut MemberSession,
    now_ms: u64,
) -> Result<Vec<Vec<u8>>> {
    if info.role == ROLE_LEAF && profile.role != ROLE_LEAF {
        return Err(Error::msg("a small device joins by its own invitation, not at home from a phone"));
    }
    let state = set.state();
    let signer = signer_of(set, key);
    let own_hash = Key::es256(own.to_vec()).hash();
    let own_device = state.device_by_key(&own_hash);
    // A root gives what the profile allows; it makes admins later, from the
    // admin key the joiner's hellos offer.
    let choice = Choice { rights: profile.rights, admin: None, guarded: false };
    let d = decide::joiner_record(&state, signer, own_device, joiner, info, profile, Checked::default(), choice)
        .map_err(|r| Error::msg(format!("the device cannot join: {}", r.message())))?;
    let joiner_hash = d.key.hash();
    set.write_record(&state, key, Kind::device(d), now_ms)
        .map_err(|e| Error::msg(format!("cannot write the device's record: {e}")))?;
    let state = set.state();
    let by = Key::es256(key.public()).hash();
    let (w, parts) = Welcome::build(set, &state, &by, &joiner_hash, now_ms)
        .map_err(|_| Error::msg("the group is too large for a Welcome"))?;
    session.welcome(&w, &parts).map_err(|e| Error::msg(format!("cannot send the Welcome: {e:?}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use cbb_core::identity::FileKey;
    use cbb_core::join::PairExporter;
    use cbb_core::join::invitation::{Invitation, JoinerAttempts, Network};
    use cbb_core::join::session::{Adb, Joined, JoinerSession};
    use cbb_core::join::welcome::Joining;
    use cbb_core::records::body::{ROLE_MEMBER, ROLE_PHONE};
    use cbb_member::own::Own;

    use super::*;

    fn point(k: &dyn ExternalKey) -> [u8; 65] {
        k.public().try_into().unwrap()
    }

    /// A group a phone made, with its root key, and the session's ends up to
    /// the approval at home.
    fn approved(
        tag: &str,
        role: u64,
    ) -> (RecordSet, Own, JoinerSession, JoinerAttempts, MemberSession, Info, [u8; 65]) {
        let dir = std::env::temp_dir().join(format!("cbb-ffi-pair06-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = cbb_member::founding::Me { name: "phone", os: 0, caps: 0 };
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        cbb_member::founding::found_with(&dir, &me, now, &|| None).unwrap();
        let own = Own::load(&dir).unwrap();
        let set = cbb_member::set::load(&dir, &cbb_member::set::local_key(&dir).unwrap()).unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        let joiner_key = FileKey::new(&cbb_core::identity::new_key().unwrap()).unwrap();
        let (jp, mp) = (point(&joiner_key), point(own.member.as_ref()));
        let x = [7u8; cbb_core::alpn::PAIR_EXPORTER_LEN];
        let st = set.state();
        let adb = Adb {
            group: cbb_core::format::DeviceId(st.group.0),
            device: cbb_core::format::DeviceId(own.device().0),
            name: "phone".into(),
        };
        let mut attempts = JoinerAttempts::default();
        let info = Info::new("laptop", 1, role);
        let (mut open, digits) = cbb_member::admitting::home_window(now, std::time::Duration::from_secs(300));
        let (mut j, m64) = JoinerSession::start(
            &mut attempts,
            info.clone(),
            Invitation::typed(open.invitation.id, &digits).unwrap(),
            Joining::Ordinary,
            jp,
            mp,
            PairExporter::exported_by_platform_tls(x),
        )
        .unwrap();
        let mut m = MemberSession::new(mp, jp, adb, PairExporter::exported_by_platform_tls(x));
        let m65 = m.start_invited(&mut open, Network::Home, &m64, now).unwrap();
        let r = j.reply(&m65).unwrap();
        m.confirm(&r.send, &mut open, now).unwrap();
        assert!(m.approved(), "the window's digits approve the joiner");
        (set, own, j, attempts, m, info, jp)
    }

    #[test]
    fn the_root_phone_admits_a_computer_and_the_computer_keeps_the_group() {
        let (mut set, own, mut j, _a, mut m, info, jp) = approved("root", ROLE_MEMBER);
        let root = own.root.clone().unwrap();
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        let frames =
            admit(&mut set, root.as_ref(), &own.member.public(), &jp, &info, &home_profile(info.role), &mut m, now)
                .unwrap();
        let hash = Key::es256(jp.to_vec()).hash();
        let d = set.state().device_by_key(&hash).cloned().expect("the joiner's record");
        assert_eq!(d.rights, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS);
        assert!(d.admin.is_none(), "the root makes admins later");
        let mut joined = None;
        for f in &frames {
            if let Joined::Done(a) = j.take(f, now).unwrap() {
                joined = Some(a);
            }
        }
        let a = joined.expect("the Welcome checked");
        assert_eq!(a.set.digest(), set.digest());
    }

    #[test]
    fn a_device_that_may_not_admit_writes_nothing() {
        let (mut set, own, _j, _a, mut m, info, jp) = approved("nobody", ROLE_PHONE);
        let before = set.digest();
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        // The member key is no admin key: the records refuse it.
        let e = admit(
            &mut set,
            own.member.as_ref(),
            &own.member.public(),
            &jp,
            &info,
            &home_profile(info.role),
            &mut m,
            now,
        )
        .unwrap_err();
        assert!(e.to_string().contains("may not admit"), "{e}");
        assert_eq!(set.digest(), before);
    }

    #[test]
    fn a_small_device_does_not_join_at_home() {
        let (mut set, own, _j, _a, mut m, mut info, jp) = approved("leaf", ROLE_MEMBER);
        info.role = ROLE_LEAF;
        let root = own.root.clone().unwrap();
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        assert!(
            admit(&mut set, root.as_ref(), &own.member.public(), &jp, &info, &home_profile(ROLE_MEMBER), &mut m, now)
                .is_err()
        );
    }
}
