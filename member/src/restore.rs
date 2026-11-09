// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Restoring a group on a new phone with the group's recovery key, read
//! from the QR code of its sheet (docs/protocol.md, section 10, "The
//! recovery key"), for an app whose keys the core does not hold (the Aurora
//! app's in OP-TEE). The recovery key issues the phone a member certificate
//! under its own admin CA; a member of the group that browsing finds by the
//! sheet's tag takes it on a connection that carries records only and sends
//! the group's first root in its hello. The phone checks the records before
//! it signs anything, then starts its member with that certificate and
//! claims the group for a new root of its own with the recovery key
//! (cbb_member_manage's `recover` with the sheet). The claim waits the
//! group's delay, unless the root cancels it; the app's takeover then makes
//! the phone the root. As the Swift kit's Restore.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cbb_core::authority::Record;
use cbb_core::certs::{self, Cert, DeviceId, Usage};
use cbb_core::clip::Hello;
use cbb_core::group::Records;
use cbb_core::identity::{ExternalKey, FileKey};
use cbb_core::recovery;
use cbb_core::tls::{self as core_tls, Session};
use cbb_core::wire;

use crate::error::{Context as _, Error, Result};
use crate::tls;

/// The typed key is not enough on a new phone: the QR code carries the
/// key's admin CA and the group's tag.
pub const NEEDS_QR: &str = "scan the QR code of the recovery sheet: on a new phone the typed key is not enough";
/// The group has no recovery key now, or another one.
pub const NOT_THE_KEY: &str = "this is not the group's recovery key now: the root removed it or made a new one";
/// No member of the group answered.
pub const NO_MEMBER: &str =
    "no device of the group was found on this network: turn on a phone or a computer of the group and try again";

/// How long the member stays quiet before the exchange counts as done; it
/// closes after 5 s.
const QUIET: Duration = Duration::from_secs(2);
/// How long the connection and the member's hello take at most.
const HELLO_WAIT: Duration = Duration::from_secs(10);
/// The most records one exchange takes: the core's set keeps no more.
const MAX_RECORDS: usize = 4096;

/// A restore under way: the recovery key from the sheet and the member
/// certificate it issued this phone.
pub struct Restore {
    key: Arc<FileKey>,
    admin: [u8; 32],
    tag: String,
    /// The recovery key's admin CA, from the QR code.
    pub admin_ca: Cert,
    /// This phone's new device ID.
    pub device: DeviceId,
    /// This phone's member certificate, from the recovery key's admin CA.
    pub cert: Vec<u8>,
}

/// What a member sent on a records-only connection.
pub struct Fetched {
    /// The group's first root, DER, from the member's hello.
    pub group_ca: Option<Vec<u8>>,
    pub records: Vec<Record>,
    /// The member's certificate chain from the TLS handshake.
    pub peer_chain: Vec<Vec<u8>>,
}

/// The group as the records a member sent show it, checked.
pub struct Restored {
    pub group_ca: Cert,
    /// The group's records, as the member sent them and the set took them.
    pub records: Records,
}

impl Restore {
    /// Reads the sheet's QR code (or text, which is refused with NEEDS_QR)
    /// and issues this phone's member key point (uncompressed) a member
    /// certificate under the recovery key's admin CA, valid from now (Unix
    /// seconds).
    pub fn new(sheet: &str, point: &[u8], now: i64) -> Result<Restore> {
        let s = recovery::read(sheet).map_err(|r| Error::msg(r.message()))?;
        let (Some(der), Some(tag)) = (s.cert.clone(), s.group.clone()) else {
            return Err(Error::msg(NEEDS_QR));
        };
        let admin_ca = Cert::parse(&der).map_err(|e| e.context("the sheet's admin CA"))?;
        let admin = s.admin().ok_or_else(|| Error::msg("the recovery key cannot be encoded"))?;
        if admin_ca.key_hash() != admin {
            return Err(Error::msg("the sheet's admin CA is for another key"));
        }
        let pkcs8 = s.pkcs8().ok_or_else(|| Error::msg("the recovery key cannot be encoded"))?;
        let key = Arc::new(FileKey::new(&pkcs8)?);
        let device = DeviceId::random();
        let cert = cbb_core::issue::member(&device, point, &admin_ca, now, &mut |tbs: &[u8]| {
            cbb_core::identity::sign_external(&*key, tbs)
        })?;
        Ok(Restore { key, admin, tag, admin_ca, device, cert })
    }

    /// The group's tag from the sheet, which browsing looks for.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The recovery key, which signs the claim and nothing else.
    pub fn key(&self) -> Arc<dyn ExternalKey> {
        self.key.clone()
    }

    /// The chain this phone presents in TLS, leaf first.
    pub fn chain(&self) -> Vec<Vec<u8>> {
        vec![self.cert.clone(), self.admin_ca.der.clone()]
    }

    /// Exchanges records with the member at addr on a connection that
    /// carries records only: this phone's hello without a digest, so the
    /// member sends all its records; then send, once the member's hello
    /// came; then whatever arrives until it is quiet. member signs this
    /// phone's side of the handshake with its member key.
    pub fn fetch(
        &self,
        addr: SocketAddr,
        member: Arc<dyn ExternalKey>,
        name: &str,
        os: &str,
        send: &[Record],
    ) -> Result<Fetched> {
        let what = format!("restoring from {addr}");
        let sock = TcpStream::connect_timeout(&addr, HELLO_WAIT).context(what.clone())?;
        sock.set_read_timeout(Some(HELLO_WAIT)).context(what.clone())?;
        let _ = sock.set_nodelay(true);
        let cfg = core_tls::restore_client(&self.chain(), member, &tls::clock())?;
        let mut s = Session::client(Arc::new(cfg), core_tls::server_name(None))?;
        tls::handshake(&mut s, &sock, &what)?;
        let peer_chain: Vec<Vec<u8>> =
            s.peer_certificates().unwrap_or_default().iter().map(|c| c.as_ref().to_vec()).collect();
        let mut t = tls::Stream::new(s, sock);
        let hello = wire::hello(
            &Hello { wall: crate::uptime::wall_ms(), current: None },
            String::new(),
            "phone",
            name,
            os,
            &wire::DeviceInfo::default(),
            None,
            "",
            None,
            &[],
            "hardware",
            None,
            (0, 0),
            None,
        );
        t.write_all(&wire::frame(&hello)?).context(what.clone())?;
        let out = read_all(&mut t, send, &what);
        t.close();
        let (group_ca, records) = out?;
        Ok(Fetched { group_ca, records, peer_chain })
    }

    /// Checks what a member sent before this phone signs anything: the
    /// group's first root carries the sheet's tag, the records name the
    /// recovery key in their state and lead to a root that issued its admin
    /// CA, and the member's certificate verifies to a root on the path and
    /// names a device the records list. now is Unix seconds.
    pub fn check(&self, f: &Fetched, now: i64) -> Result<Restored> {
        let der = f.group_ca.as_deref().ok_or_else(|| Error::msg("the member did not send the group's first root"))?;
        let group_ca = Cert::parse(der).map_err(|e| e.context("the group's first root"))?;
        if certs::tag(&group_ca) != self.tag {
            return Err(Error::msg("the member is of another group than the sheet"));
        }
        certs::check_root(&group_ca).map_err(|e| e.context("the group's first root is not a root"))?;
        let mut rs = Records::new(&group_ca);
        let _ = rs.add_all(&f.records);
        let state = rs.state();
        if state.recovery.map(|h| h.0) != Some(self.admin) || rs.revoked(&self.admin) {
            return Err(Error::msg(NOT_THE_KEY));
        }
        let trusted = rs.path_certs();
        if !trusted.iter().any(|r| certs::check_admin_ca(&self.admin_ca, r).is_ok()) {
            return Err(Error::msg("no root of the group issued the recovery key's admin CA"));
        }
        let chain = f.peer_chain.iter().map(|c| Cert::parse(c)).collect::<Result<Vec<Cert>>>()?;
        let peer = certs::verify_member(&chain, &trusted, now, Usage::Server)
            .map_err(|e| e.context("the member's certificate is not from the group"))?;
        if !rs.devices().iter().any(|d| d.id == peer.as_str()) || rs.refused(&chain).is_some() {
            return Err(Error::msg("the records do not list the member"));
        }
        Ok(Restored { group_ca, records: rs })
    }
}

/// Reads the member's hello and records on t, sending send once the hello
/// came, until the member is quiet or closes.
fn read_all(t: &mut tls::Stream, send: &[Record], what: &str) -> Result<(Option<Vec<u8>>, Vec<Record>)> {
    let mut group_ca = None;
    let mut hello = false;
    let mut records: Vec<Record> = Vec::new();
    let start = Instant::now();
    loop {
        let wait = if hello { QUIET } else { HELLO_WAIT.saturating_sub(start.elapsed()).max(Duration::from_millis(1)) };
        t.sock.set_read_timeout(Some(wait)).context(what.to_string())?;
        let m = match read_frame(t) {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(e) => {
                if !hello {
                    return Err(e.context("the member sent no hello"));
                }
                return Ok((group_ca, records));
            }
        };
        if !hello {
            if m.kind != "hello" {
                return Err(Error::msg("the member did not start with a hello"));
            }
            let (_, body) = wire::decode_hello(m.hello.as_ref())?;
            group_ca = body.group_ca;
            hello = true;
            if !send.is_empty() {
                let msg = wire::Message { kind: "records".into(), records: send.to_vec(), ..Default::default() };
                t.write_all(&wire::frame(&msg)?).context(what.to_string())?;
            }
        } else if m.kind == "records" && records.len() + m.records.len() <= MAX_RECORDS {
            records.extend(m.records);
        }
    }
}

/// One message from t; None for a chunk frame, which this connection does
/// not use.
fn read_frame(t: &mut tls::Stream) -> Result<Option<wire::Message>> {
    let mut head = [0u8; 4];
    t.read_exact(&mut head).context("the connection broke")?;
    if head[0] & 0x80 != 0 {
        let n = (u32::from_be_bytes(head) & 0x7fff_ffff) as usize;
        if n > wire::MAX_CHUNK_FRAME {
            return Err(Error::msg("a chunk frame is too large"));
        }
        let mut b = vec![0u8; n];
        t.read_exact(&mut b).context("the connection broke")?;
        return Ok(None);
    }
    let size = wire::frame_len(head, wire::MAX_FRAME)?;
    let mut data = vec![0u8; size];
    t.read_exact(&mut data).context("the connection broke")?;
    Ok(Some(wire::decode(&data)?))
}

/// Restores the group of the sheet: tries addrs, or else the members that
/// browsing finds for up to wait, and takes the records from the first
/// whose answer checks. A member of another group, or one that does not
/// answer, is skipped; a group whose recovery key is no longer this one
/// ends it.
pub fn restore(
    sheet: &str,
    member: Arc<dyn ExternalKey>,
    name: &str,
    os: &str,
    addrs: &[SocketAddr],
    wait: Duration,
) -> Result<(Restore, Restored, SocketAddr)> {
    let now = crate::uptime::wall_ms() / 1000;
    let r = Restore::new(sheet, &member.public(), now)?;
    let found = if addrs.is_empty() { crate::discovery::find_group(r.tag(), wait)? } else { vec![addrs.to_vec()] };
    let mut last = Error::msg(NO_MEMBER);
    for addrs in found {
        for addr in addrs {
            match r.fetch(addr, member.clone(), name, os, &[]).and_then(|f| r.check(&f, now)) {
                Ok(g) => return Ok((r, g, addr)),
                Err(e) if e.to_string().contains(NOT_THE_KEY) => return Err(e),
                Err(e) => last = e,
            }
        }
    }
    Err(last)
}
