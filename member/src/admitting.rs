// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A computer admits a device that pairs with it at home (format section
//! 8, `cbb-pair/3` on the member port): both persons check the code, then
//! this device writes the joiner's device record with the key it signs
//! the group's records with, keeps the joiner's first keys statement and
//! sends the Welcome. It runs inside the pairing window the service opens
//! (`Mesh::on_pair`).

use std::net::TcpStream;

use cbb_core::join::PairExporter;
use cbb_core::join::info::Info;
use cbb_core::join::session::{Adb, MemberSession};
use cbb_core::join::welcome::Welcome;
use cbb_core::records::Key;
use cbb_core::records::body::{
    CAP_HUB, Device, Kind, RIGHT_HUB, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_MEMBER, ROLE_WATCH,
};
use cbb_core::tls::bykey;

use crate::error::{Error, Result};
use crate::join::{self, Ask, Way};
use crate::mesh::Mesh;
use crate::tls;

/// The rights a device admitted at home gets: it reads, sends and takes
/// secrets; a watch only reads, through its phone. A member with the cap
/// hub may also be one of the group's main hubs.
pub(crate) fn rights_of(role: u64, caps: u64) -> u64 {
    if role == ROLE_WATCH {
        return RIGHT_READ;
    }
    let hub = if role == ROLE_MEMBER && caps & CAP_HUB != 0 { RIGHT_HUB } else { 0 };
    RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS | hub
}

/// Runs the member's side of a pairing at home over its TLS session:
/// `ask` shows the code and gives the person's answer. Gives what the
/// joiner said of itself once it is in the group.
pub fn at_home(
    mesh: &Mesh,
    sock: TcpStream,
    session: tls::Session,
    exporter: PairExporter,
    ask: Ask<'_>,
) -> Result<Info> {
    let joiner = bykey::peer_key(session.peer_certificates()).ok_or_else(|| Error::msg("the device showed no key"))?;
    let own: [u8; 65] = mesh
        .own()
        .member_key()
        .public()
        .try_into()
        .map_err(|_| Error::msg("this device's member key is not a P-256 point"))?;
    let state = mesh.state();
    let me = mesh.device();
    let adb = Adb {
        group: cbb_core::format::DeviceId(state.group.0),
        device: cbb_core::format::DeviceId(me.0),
        name: state.device(&me).map(|d| d.name.clone()).unwrap_or_default(),
    };
    if crate::writers::signer(mesh.own(), &state).is_none() {
        return Err(Error::msg("this device admits no one: it holds neither the group's root key nor an admin key"));
    }
    let session_m = MemberSession::new(own, joiner, adb, exporter);
    let mut stream = tls::Stream::new(session, sock);
    let joiner_key = Key::es256(joiner.to_vec());
    let now = || crate::uptime::wall_ms().max(0) as u64;
    let mut statement = None;
    let mut pop_holds = false;
    let info = join::member(&mut stream, session_m, Way::Home, ask, &now, &mut |info, s| {
        statement.clone_from(&info.keys);
        pop_holds = s.admin_pop_holds();
        mesh.write(|set, signer| {
            let st = set.state();
            let by_root = st.roots.last() == Some(&Key::es256(signer.public()).hash());
            let mut d = Device::new(joiner_key.clone(), &info.name, info.role);
            d.rights = rights_of(info.role, info.caps);
            if !by_root {
                // An admin grants only the base rights (rule 3): the root
                // alone lets a device be a hub.
                d.rights &= !RIGHT_HUB;
            }
            if info.role == ROLE_MEMBER {
                d.caps = info.caps;
            }
            d.os = info.os;
            set.write_record(&st, signer, Kind::device(d), now())
                .map_err(|e| Error::msg(format!("cannot write the device's record: {e}")))?;
            let st = set.state();
            let by = Key::es256(signer.public()).hash();
            let (w, parts) = Welcome::build(set, &st, &by, &joiner_key.hash(), now())
                .map_err(|_| Error::msg("the group is too large for a Welcome"))?;
            s.welcome(&w, &parts).map_err(|e| Error::msg(format!("cannot send the Welcome: {e:?}")))
        })
    });
    if let (Ok(_), Some(env)) = (&info, statement) {
        mesh.take_statement(&env)?;
    }
    if let Ok(i) = &info {
        keep_admin_key(mesh, &joiner_key, i, pop_holds)?;
    }
    info
}

/// On the group's root, keeps the admin key the joiner offered once its
/// proof over the session holds, for cbb admin to write into its record
/// later (offered.rs). An admin that is not the root keeps none: the
/// device pairs with the root to become an admin.
fn keep_admin_key(mesh: &Mesh, joiner: &Key, info: &Info, pop_holds: bool) -> Result<()> {
    let Some(admin) = info.admin_key() else { return Ok(()) };
    let st = mesh.state();
    let root = mesh.own().root.as_ref().is_some_and(|k| st.roots.last() == Some(&Key::es256(k.public()).hash()));
    if !root {
        return Ok(());
    }
    if !pop_holds {
        return Err(Error::msg(
            "the device's admin key does not prove itself over this pairing; it is in the group, and no admin",
        ));
    }
    let id = crate::roster::id_text(&joiner.device_id());
    crate::offered::keep(mesh.dir(), &id, admin.public())
}

#[cfg(test)]
mod tests;

/// What other modules' tests build on: a group whose root this computer
/// holds.
#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) use super::tests::root_mesh;
}
