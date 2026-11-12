// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A device's registration with the relay: TLS with
//! its member certificate (or the certificate of its server key and the
//! group's credentials), then the proof that it holds its WireGuard key,
//! bound to this TLS session, as with the forwarder. The relay keeps the
//! registration open while the device is registered.

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use cbb_core::certs::{self, Cert, Usage};
use cbb_core::credential::{self, Presented};
use gotatun::x25519;

use super::records::refused_here;
use super::server::{Inner, Member, spawn};
use super::wire::{self, Challenge, Claim, MAX_CLAIM, Welcome};
use crate::error::{Error, Result};

/// The most certificates a device may present: its member certificate,
/// its admin CA and the group's roots; the roots it may show with its
/// credentials; and the records in a claim, whose signatures the relay
/// checks.
const MAX_CHAIN: usize = 8;
const MAX_ROOTS: usize = 8;
const MAX_CLAIM_RECORDS: usize = 1024;

/// The label of the key, from the registration's TLS, under which a device
/// proves its WireGuard key.
const PROOF_LABEL: &[u8] = b"cbb relay key";

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// The IP address of a connection's remote end, IPv4 when it is mapped.
pub fn addr_of(c: &TcpStream) -> Option<IpAddr> {
    c.peer_addr().ok().map(|a| match a.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        a => a,
    })
}

/// The device a registration's certificates name.
pub(super) enum Device {
    /// A member certificate with its chain to the root of a group the relay
    /// serves: that group's tag and root, and the device's ID.
    Member { tag: String, root: Box<Cert>, device: String },
    /// A server certificate alone, which names neither, for a device that
    /// registers with the group's credentials.
    Credentialed,
}

/// The root among the certificates that names the group tag.
fn root_of(chain: &[Cert], tag: &str) -> Option<Cert> {
    chain.iter().skip(1).find(|c| c.is_ca && c.signed_by(c) && certs::tag(c) == tag).cloned()
}

impl Inner {
    /// Checks the certificates a device presented, as Go's groupOf. A root
    /// that the device presents counts only if the relay serves its group.
    pub(super) fn group_of(&self, chain: &[Cert], now: i64) -> std::result::Result<Device, String> {
        if chain.is_empty() || chain.len() > MAX_CHAIN {
            return Err("relay: the device presented no member certificate chain".into());
        }
        if certs::device_of(&chain[0]).is_err() {
            if chain.len() == 1 && !chain[0].is_ca {
                return Ok(Device::Credentialed);
            }
            return Err("relay: the device's certificate names no device".into());
        }
        let roots: Vec<Cert> = chain
            .iter()
            .skip(1)
            .filter(|c| c.is_ca && c.signed_by(c) && (self.cfg.open || self.allowed.contains(&certs::tag(c))))
            .cloned()
            .collect();
        for root in roots {
            if let Ok(dev) = certs::verify_member(chain, std::slice::from_ref(&root), now, Usage::Client) {
                let tag = certs::tag(&root);
                return Ok(Device::Member { tag, root: Box::new(root), device: dev.as_str().to_string() });
            }
        }
        Err("relay: the device is not of a group this relay serves".into())
    }

    /// Checks a device that registers with credentials: the period's hubs'
    /// and members' credentials, which list the key of its server
    /// certificate among the members; and on a relay that serves a fixed
    /// list of groups, the period credential, signed by one of the roots the
    /// device shows, which must be the root of a group the relay serves.
    fn credentialed(&self, leaf: &Cert, c: &Claim, now_ms: i64) -> std::result::Result<Presented, String> {
        let p = match credential::check_presented(&c.credentials, now_ms) {
            Err(e) if e.message().contains("expired") => {
                return Err("the group's credentials expired; the group's root starts a new period".into());
            }
            Err(_) => return Err("the group's credentials do not verify".into()),
            Ok(p) => p,
        };
        match &p.members {
            None => return Err("the device sent no members' credential".into()),
            Some(m) if !m.members.contains(&leaf.key_hash()) => {
                return Err("the group's members' credential does not list this device".into());
            }
            Some(_) => {}
        }
        if self.cfg.open {
            return Ok(p);
        }
        let Some((_, period_root)) = &p.period else { return Err("the device showed no root of its group".into()) };
        if c.roots.len() > MAX_ROOTS {
            return Err("the device showed no root of its group".into());
        }
        for der in &c.roots {
            let Ok(root) = Cert::parse(der) else { continue };
            if root.is_ca
                && root.signed_by(&root)
                && root.spki == *period_root
                && self.allowed.contains(&certs::tag(&root))
            {
                return Ok(p);
            }
        }
        Err("the device is not of a group this relay serves".into())
    }

    /// Takes the devices' TLS connections.
    pub(super) fn accept_registrations(self: Arc<Self>, ln: TcpListener) {
        for conn in ln.incoming() {
            if self.stopping() {
                return;
            }
            let Ok(conn) = conn else { continue };
            let from = addr_of(&conn);
            if !self.take_slot(from) {
                let _ = conn.shutdown(Shutdown::Both);
                continue;
            }
            let inner = self.clone();
            match spawn(move || inner.serve_registration(conn, from)) {
                Ok(t) => self.keep(t),
                Err(_) => self.free_slot(from),
            }
        }
    }

    /// Registers one device and holds its registration while the
    /// connection lasts.
    fn serve_registration(self: Arc<Self>, raw: TcpStream, from: Option<IpAddr>) {
        let r = self.register(&raw, from);
        self.free_slot(from);
        let (m, mut tls) = match r {
            Ok(x) => x,
            Err(_) => {
                let _ = raw.shutdown(Shutdown::Both);
                return;
            }
        };
        // The device sends nothing more; reading tells when it goes.
        tls.sock.clear();
        let mut buf = [0u8; 512];
        while !self.stopping() {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let mut st = self.lock();
        self.drop_locked(&mut st, &m);
        st.members.remove(&m.id);
    }

    /// Runs a registration's setup.
    fn register(
        self: &Arc<Self>,
        raw: &TcpStream,
        from: Option<IpAddr>,
    ) -> Result<(Arc<Member>, rustls::StreamOwned<rustls::ServerConnection, wire::Deadline>)> {
        let wait = self.lock().setup_wait;
        let sock = raw.try_clone().map_err(|e| Error::msg(format!("relay: {e}")))?;
        let _ = sock.set_nodelay(true);
        // One deadline for the whole setup: the handshake, the claim and the
        // answer, however the device spaces its bytes.
        let sock = wire::Deadline::new(sock, wait);
        let conn = rustls::ServerConnection::new(self.tls.clone()).map_err(|e| Error::msg(format!("relay: {e}")))?;
        let mut s = rustls::StreamOwned::new(conn, sock);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).map_err(|e| Error::msg(format!("relay: {e}")))?;
        }
        if s.conn.alpn_protocol() != Some(crate::relay::PROTOCOL) {
            return Err(Error::msg("relay: the device does not speak the registration protocol"));
        }
        let chain: Vec<Cert> = s
            .conn
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .take(MAX_CHAIN + 1)
            .map(|c| Cert::parse(c))
            .collect::<Result<_>>()?;
        let device = self.group_of(&chain, now_secs()).map_err(Error::msg)?;
        let cred = matches!(device, Device::Credentialed);
        let eph = x25519::StaticSecret::from(certs::random_bytes::<32>());
        let e = x25519::PublicKey::from(&eph);
        wire::write_frame(&mut s, &Challenge { e: e.as_bytes().to_vec(), roots: cred && !self.cfg.open }, MAX_CLAIM)?;
        let claim: Claim = serde_json::from_slice(&wire::read_frame(&mut s, MAX_CLAIM)?)
            .map_err(|_| Error::msg("relay: a claim that does not decode"))?;
        let refuse = |s: &mut rustls::StreamOwned<rustls::ServerConnection, wire::Deadline>, msg: &str| {
            let _ = wire::write_frame(s, &Welcome { error: msg.to_string(), ..Welcome::default() }, MAX_CLAIM);
            Error::msg(msg.to_string())
        };
        let Ok(key) = <[u8; 32]>::try_from(&claim.key[..]) else {
            return Err(refuse(&mut s, "the WireGuard key is not 32 bytes"));
        };
        let shared = eph.diffie_hellman(&x25519::PublicKey::from(key));
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
        if claim.records.len() > MAX_CLAIM_RECORDS {
            return Err(refuse(&mut s, "too many records"));
        }
        let leaf = chain[0].key_hash();
        let psk = certs::random_bytes::<32>();
        let raw_clone = raw.try_clone().map_err(|e| Error::msg(format!("relay: {e}")))?;
        let (tag, name, presented, root) = match device {
            Device::Credentialed => match self.credentialed(&chain[0], &claim, now_secs() * 1000) {
                Ok(p) => (format!("period {}", p.tag), credential::pseudonym(&leaf), Some(p), None),
                Err(msg) => return Err(refuse(&mut s, &msg)),
            },
            Device::Member { tag, root, device } => (tag, device, None, Some(*root)),
        };
        let mut st = self.lock();
        let id = st.next_id();
        let share = self.share_locked(&st, &tag);
        drop(st);
        let m = Arc::new(Member {
            id,
            tag: tag.clone(),
            device: name,
            leaf,
            chain: chain.clone(),
            key,
            psk,
            from: addr_of(raw),
            raw: raw_clone,
            share,
        });
        // The group's registrations that check records take turns, until
        // this one has added its device.
        let mut turn = None;
        let mut recs = None;
        if let Some(root) = &root {
            // A registration the relay would refuse anyway sends it no
            // records to keep.
            let refusal = self.admit_locked(&mut self.lock(), &m, None).err();
            if let Some(msg) = refusal {
                return Err(refuse(&mut s, &msg));
            }
            // The relay keeps the group's records once verified, and checks
            // only the ones a claim brings that it does not have; the
            // group's other registrations wait meanwhile.
            turn = Some(self.lock_tag(&tag));
            let root = root_of(&chain, &tag).unwrap_or_else(|| root.clone());
            let (rs, fresh, err) = self.check_records(&tag, &root, from, &claim.records);
            if let Some(msg) = err {
                self.forget_records(&tag);
                return Err(refuse(&mut s, &msg));
            }
            if let Some(rs) = &rs {
                let set = rs.lock().unwrap_or_else(|e| e.into_inner());
                let mut st = self.lock();
                if fresh {
                    // The devices the new records remove go now, whatever
                    // becomes of this registration: the records stay with
                    // the group's devices.
                    let gone: Vec<Arc<Member>> = st
                        .groups
                        .get(&tag)
                        .map(|g| g.values().filter(|o| refused_here(&set.set, &o.chain).is_some()).cloned().collect())
                        .unwrap_or_default();
                    for o in gone {
                        self.drop_locked(&mut st, &o);
                    }
                }
                drop(st);
                // A group the relay holds no verified record of is one it
                // knows nothing about: only records it holds can refuse a
                // device.
                let why = (!set.set.is_empty()).then(|| refused_here(&set.set, &chain)).flatten();
                drop(set);
                if let Some(why) = why {
                    self.forget_records(&tag);
                    return Err(refuse(&mut s, &why));
                }
            }
            recs = rs;
        }
        let mut st = self.lock();
        if self.stopping() {
            drop(st);
            return Err(refuse(&mut s, "the relay is stopping"));
        }
        // What was checked before the records may have changed meanwhile.
        let mut refusal = None;
        let mut leaving = None;
        if let Some(p) = &presented {
            refusal = Inner::check_period_locked(&st, &tag, p);
            leaving = Inner::leaving_locked(&st, &tag, p);
        }
        if refusal.is_none() {
            let gone = leaving.as_ref().map(|keep| move |o: &Member| !keep.contains(&o.leaf));
            refusal = match &gone {
                Some(f) => self.admit_locked(&mut st, &m, Some(f)).err(),
                None => self.admit_locked(&mut st, &m, None).err(),
            };
        }
        if let Some(msg) = refusal {
            drop(st);
            if recs.is_some() {
                self.forget_records(&tag);
            }
            return Err(refuse(&mut s, &msg));
        }
        let addr = match self.add_locked(&mut st, &m) {
            Ok(a) => a,
            Err(e) => {
                drop(st);
                if recs.is_some() {
                    self.forget_records(&tag);
                }
                return Err(e);
            }
        };
        if let Some(p) = &presented {
            self.take_period_locked(&mut st, &tag, p);
        }
        drop(st);
        drop(turn);
        let relay_key = x25519::PublicKey::from(&x25519::StaticSecret::from(self.cfg.keys.wireguard));
        let w = Welcome {
            error: String::new(),
            key: Some(relay_key.as_bytes().to_vec()),
            psk: Some(psk.to_vec()),
            addr: addr.to_string(),
        };
        if let Err(e) = wire::write_frame(&mut s, &w, MAX_CLAIM) {
            let mut st = self.lock();
            self.drop_locked(&mut st, &m);
            st.members.remove(&m.id);
            return Err(e);
        }
        let _ = s.sock.flush();
        s.sock.clear();
        Ok((m, s))
    }
}
