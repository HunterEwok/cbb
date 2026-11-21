// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A registration of 0.6 with the relay (`cbb-relay/3`, D-106): the device
//! shows a certificate of its server key alone, which names neither a
//! device nor a group, proves its WireGuard key bound to this TLS session
//! as before, and is taken by its period's credentials only
//! (`cbb_core::blind::credential`): the hubs' credential, the members'
//! credential that lists its server key, and on a relay that serves a list
//! of groups the period credential, signed by the root of a group on the
//! list. The relay never sees a record or a device ID; it takes no other
//! registration.

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use cbb_core::blind::credential::{Credential, TYPE_HUBS, TYPE_MEMBERS, TYPE_PERIOD};
use cbb_core::certs::{self, Cert};
use gotatun::x25519;

use super::period::Shown;
use super::register::addr_of;
use super::server::{Inner, Member};
use super::wire::Deadline;
use super::wire3::{self, MAX_FRAME, Register};
use crate::error::{Error, Result};

const PROOF_LABEL: &[u8] = b"cbb relay key";

type Tls = rustls::StreamOwned<rustls::ServerConnection, Deadline>;

/// A group of 0.6 the relay serves, as `-group` names it: its first root
/// key and the two halves of its recovery key, in hex, separated by
/// colons. The Group ID is computed from them, so a period of the group is
/// taken only from its root.
#[derive(Clone, Debug)]
pub struct Listed {
    pub root: Vec<u8>,
    pub recovery: Vec<u8>,
    pub recovery2: Vec<u8>,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

impl Listed {
    pub fn parse(s: &str) -> Result<Listed> {
        let bad = || {
            Error::msg(format!(
                "relay: {s:?} is not a group of 0.6: its root key, recovery key and second recovery key in hex, separated by colons"
            ))
        };
        let parts: Vec<&str> = s.trim().split(':').collect();
        let [root, recovery, recovery2] = parts.as_slice() else { return Err(bad()) };
        let (Some(root), Some(recovery), Some(recovery2)) = (unhex(root), unhex(recovery), unhex(recovery2)) else {
            return Err(bad());
        };
        if root.len() != 65 || recovery.len() != 65 || recovery2.is_empty() {
            return Err(bad());
        }
        Ok(Listed { root, recovery, recovery2 })
    }
}

/// The credentials a device showed, checked: the hubs' and the members'.
#[derive(Debug)]
pub(crate) struct Shows {
    pub hubs: Credential,
    pub members: Credential,
}

/// Checks the credentials of a registration of 0.6 for the server key of
/// hash `leaf`, at now_ms, as a relay that serves `listed` (or every
/// group, when open): one hubs' credential and one members' credential
/// listing the key, of one period, the members' signed by the period key
/// or an admin the hubs' credential lists; a period credential, when one
/// is shown, whose key signed the hubs'; on a relay with a list, a period
/// of a group on it, signed by its root, whose key the device names.
pub(crate) fn check(
    envs: &[Vec<u8>],
    leaf: &[u8; 32],
    root: Option<&[u8]>,
    listed: Option<&[Listed]>,
    now_ms: u64,
) -> std::result::Result<Shows, String> {
    let mut read = Vec::new();
    for e in envs.iter().take(3) {
        read.push(Credential::read(e).map_err(|_| "the group's credentials do not verify".to_string())?);
    }
    if read.iter().any(|c| !c.live(now_ms)) {
        return Err("the group's credentials expired; the group's root starts a new period".into());
    }
    let one = |kind| {
        let mut it = read.iter().filter(|c| c.kind == kind);
        match (it.next(), it.next()) {
            (Some(c), None) => Ok(Some(c.clone())),
            (None, _) => Ok(None),
            _ => Err("the credentials are not a hubs' credential with a members' and at most a period credential"),
        }
    };
    let hubs = one(TYPE_HUBS)?.ok_or("the device sent no hubs' credential")?;
    let members = one(TYPE_MEMBERS)?.ok_or("the device sent no members' credential")?;
    let period = one(TYPE_PERIOD)?;
    let by_period = members.signer == hubs.signer;
    let by_admin = hubs.admins.contains(&members.signer_hash().0);
    if members.group != hubs.group || !(by_period || by_admin) {
        return Err("the group's credentials do not verify".into());
    }
    if let Some(p) = &period
        && cbb_core::blind::credential::check_chain(p, &hubs, Some(&members)).is_err()
    {
        return Err("the group's credentials do not verify".into());
    }
    if !members.members.contains(leaf) {
        return Err("the group's members' credential does not list this device".into());
    }
    if let Some(listed) = listed {
        let Some(p) = &period else { return Err("the device showed no root of its group".into()) };
        let named = root.is_some_and(|r| r == p.signer.as_slice());
        let ours = listed
            .iter()
            .any(|l| l.root == p.signer && p.period_of_listed_group(&l.root, &l.recovery, &l.recovery2, &[p.group]));
        if !named || !ours {
            return Err("the device is not of a group this relay serves".into());
        }
    }
    Ok(Shows { hubs, members })
}

impl Inner {
    /// Runs a registration of 0.6 once its TLS is up.
    pub(super) fn register3(self: &Arc<Self>, raw: &TcpStream, mut s: Tls) -> Result<(Arc<Member>, Tls)> {
        let refuse = |s: &mut Tls, msg: &str| {
            let _ = s.write_all(&wire3::error(msg)).and_then(|()| s.flush());
            Error::msg(msg.to_string())
        };
        let ders = s.conn.peer_certificates().unwrap_or_default();
        let [der] = ders else { return Err(refuse(&mut s, "show the certificate of your server key alone")) };
        let cert = Cert::parse(der)?;
        if cert.is_ca || cert.public_key().len() != 65 {
            return Err(refuse(&mut s, "show the certificate of your server key alone"));
        }
        // A device is known by its pseudonym, the hash of its server key as
        // the members' credential lists it.
        let leaf = cbb_core::records::key::Key::es256(cert.public_key().to_vec()).hash().0;
        let eph = x25519::StaticSecret::from(certs::random_bytes::<32>());
        let e = x25519::PublicKey::from(&eph);
        s.write_all(&wire3::challenge(e.as_bytes(), !self.cfg.open))
            .and_then(|()| s.flush())
            .map_err(|e| Error::msg(format!("relay: {e}")))?;
        let body = match wire3::read(&mut s, MAX_FRAME) {
            Ok((_, b)) => b,
            Err(e) => return Err(refuse(&mut s, e.message())),
        };
        let claim = match Register::read(&body) {
            Ok(c) => c,
            Err(e) => return Err(refuse(&mut s, e.message())),
        };
        let shared = eph.diffie_hellman(&x25519::PublicKey::from(claim.key));
        if !shared.was_contributory() {
            return Err(refuse(&mut s, "the WireGuard key is not an X25519 key"));
        }
        let proof_key = s
            .conn
            .export_keying_material([0u8; 32], PROOF_LABEL, None)
            .map_err(|e| Error::msg(format!("relay: {e}")))?;
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(shared.as_bytes()).map_err(|_| Error::msg("relay: a bad key"))?;
        mac.update(&proof_key);
        if mac.verify_slice(&claim.proof).is_err() {
            return Err(refuse(&mut s, "the device does not hold that WireGuard key"));
        }
        let now_ms = u64::try_from(crate::uptime::wall_ms()).unwrap_or(0);
        let listed = (!self.cfg.open).then_some(self.listed.as_slice());
        let shows = match check(&claim.credentials, &leaf, claim.root.as_deref(), listed, now_ms) {
            Ok(x) => x,
            Err(msg) => return Err(refuse(&mut s, &msg)),
        };
        // The period's tag names the group here, as the list of refused
        // groups names it.
        let tag = format!("period {}", certs::hex(&shows.hubs.group));
        let shown = Shown {
            signer: shows.hubs.signer_hash().0,
            hubs: shows.hubs.version,
            members: Some((shows.members.version, shows.members.members.clone())),
        };
        let psk = certs::random_bytes::<32>();
        let raw_clone = raw.try_clone().map_err(|e| Error::msg(format!("relay: {e}")))?;
        let mut st = self.lock();
        let id = st.next_id();
        let share = self.share_locked(&st, &tag);
        let m = Arc::new(Member {
            id,
            tag: tag.clone(),
            device: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, leaf),
            leaf,
            key: claim.key,
            psk,
            from: addr_of(raw),
            raw: raw_clone,
            share,
        });
        if self.stopping() {
            drop(st);
            return Err(refuse(&mut s, "the relay is stopping"));
        }
        let mut refusal = Inner::check_period_locked(&st, &tag, &shown);
        if refusal.is_none() {
            refusal = match Inner::leaving_locked(&st, &tag, &shown) {
                Some(keep) => self.admit_locked(&mut st, &m, Some(&move |o: &Member| !keep.contains(&o.leaf))).err(),
                None => self.admit_locked(&mut st, &m, None).err(),
            };
        }
        if let Some(msg) = refusal {
            drop(st);
            return Err(refuse(&mut s, &msg));
        }
        let addr = self.add_locked(&mut st, &m)?;
        self.take_period_locked(&mut st, &tag, &shown);
        drop(st);
        let relay_key = x25519::PublicKey::from(&x25519::StaticSecret::from(self.cfg.keys.wireguard));
        if let Err(e) =
            s.write_all(&wire3::registered(relay_key.as_bytes(), &psk, &addr.to_string())).and_then(|()| s.flush())
        {
            let mut st = self.lock();
            self.drop_locked(&mut st, &m);
            st.members.remove(&m.id);
            return Err(Error::msg(format!("relay: {e}")));
        }
        s.sock.clear();
        Ok((m, s))
    }
}

#[cfg(test)]
mod tests;
