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
use cbb_core::records::body::{Device, Kind, RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_MEMBER, ROLE_WATCH};
use cbb_core::tls::bykey;

use crate::error::{Error, Result};
use crate::join::{self, Ask, Way};
use crate::mesh::Mesh;
use crate::tls;

/// The rights a device admitted at home gets: it reads, sends and takes
/// secrets; a watch only reads, through its phone.
fn rights_of(role: u64) -> u64 {
    if role == ROLE_WATCH { RIGHT_READ } else { RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS }
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
    let info = join::member(&mut stream, session_m, Way::Home, ask, &now, &mut |info, s| {
        statement.clone_from(&info.keys);
        mesh.write(|set, signer| {
            let mut d = Device::new(joiner_key.clone(), &info.name, info.role);
            d.rights = rights_of(info.role);
            if info.role == ROLE_MEMBER {
                d.caps = info.caps;
            }
            d.os = info.os;
            let st = set.state();
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
    info
}

#[cfg(test)]
mod tests;
