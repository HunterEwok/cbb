// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A computer joins a group at home (`cbb pair -code`, format section 8):
//! it dials a member that has a home window open (`cbb-pair/3`), proves the
//! window's six digits, CPace's password, and keeps the set the member's
//! Welcome brought before it says so, as the group's records of 0.6
//! (`set::save`). Its member key is made on first use (`own.rs`).

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cbb_core::format::KeyHash;
use cbb_core::join::info::Info;
use cbb_core::join::invitation::{Invitation, JoinerAttempts};
use cbb_core::join::session::Admitted;
use cbb_core::join::welcome::Joining;
use cbb_core::tls::bykey;

use crate::error::{Error, Result};
use crate::join::{self, Joiner};
use crate::own::Own;
use crate::tls;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the joiner waits for each step; the member's attempt has
/// `join::invitation::ATTEMPT_MS` in all.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// What a computer says of itself when it joins.
pub struct Me<'a> {
    pub name: &'a str,
    pub os: u64,
    pub caps: u64,
}

/// The home window to join with what the person gave cbb pair -code:
/// the window's QR code text (its addresses, ID and member key), or its
/// six digits, with the window found by mDNS, at `at` when given. Gives
/// the addresses to dial, the invitation and the member key's hash when
/// known.
pub fn window_of(code: &str, at: Option<SocketAddr>) -> Result<(Vec<SocketAddr>, Invitation, Option<KeyHash>)> {
    use cbb_core::join::invitation::WindowLink;
    let code = code.trim();
    if code.starts_with(cbb_core::join::invitation::WINDOW_PREFIX) {
        let link = WindowLink::parse(code).ok_or_else(|| Error::msg("this is not the QR code of a pairing window"))?;
        let invitation = link.invitation().ok_or_else(|| Error::msg("this is not the QR code of a pairing window"))?;
        let addrs: Vec<SocketAddr> = match at {
            Some(a) => vec![a],
            None => link.addrs.iter().filter_map(|a| crate::resolve(a).ok()).collect(),
        };
        if addrs.is_empty() {
            return Err(Error::msg("none of the window's addresses is one this computer can dial"));
        }
        return Ok((addrs, invitation, Some(link.fp)));
    }
    let digits: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if cbb_core::join::invitation::home_secret(&digits).is_none() {
        return Err(Error::msg(
            "type the six digits the pairing window shows (cbb pair on the group's root or an admin)",
        ));
    }
    let w = crate::discovery::find_window(crate::discovery::PAIRING_BROWSE, at)?;
    let invitation = Invitation::typed(w.id, &digits).ok_or_else(|| Error::msg("the window announces no ID"))?;
    Ok((w.addrs, invitation, w.fp))
}

/// Joins the group of the member at addr, at home, by its window's
/// invitation (`Invitation::typed` from the window's ID and six digits):
/// `fp`, when known (the window's QR code or its mDNS announcement), is
/// the hash of the member's key, which the TLS key must be. The set is
/// kept in dir before the member hears it was; an error when this device
/// is in a group already.
pub fn at_home(
    dir: &Path,
    addr: SocketAddr,
    me: &Me<'_>,
    invitation: Invitation,
    fp: Option<KeyHash>,
) -> Result<Box<Admitted>> {
    let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| Error::with(format!("cannot reach {addr}"), e))?;
    over(dir, sock, &addr.to_string(), me, invitation, fp)
}

/// at_home over a connection already made to the window's member, which
/// `who` names in the errors: the ZX Spectrum Next's link joins through
/// the Next's ESP this way (cbb next link -join).
pub fn over(
    dir: &Path,
    sock: TcpStream,
    who: &str,
    me: &Me<'_>,
    invitation: Invitation,
    fp: Option<KeyHash>,
) -> Result<Box<Admitted>> {
    over_with(dir, sock, who, me, invitation, fp, STEP_TIMEOUT, &|_| Ok(()))
}

/// Why a join's connection ended before the member's TLS handshake.
pub const NO_HANDSHAKE: &str = "the handshake with the member failed";

/// over, waiting up to `step` for each of the member's answers (a remote
/// invitation's admin confirms the device first), with `before` called
/// with the checked Welcome before the set is kept.
#[allow(clippy::too_many_arguments)]
pub fn over_with(
    dir: &Path,
    sock: TcpStream,
    who: &str,
    me: &Me<'_>,
    invitation: Invitation,
    fp: Option<KeyHash>,
    step: Duration,
    before: &dyn Fn(&Admitted) -> Result<()>,
) -> Result<Box<Admitted>> {
    std::fs::create_dir_all(dir).map_err(|e| Error::with(format!("cannot make {}", dir.display()), e))?;
    let local = crate::set::local_key(dir)?;
    if crate::set::load(dir, &local)?.is_some() {
        return Err(Error::msg("this device is in a group already: leave it first (cbb leave)"));
    }
    let mut own = Own::load(dir)?;
    let point: [u8; 65] = own
        .member_key()
        .public()
        .try_into()
        .map_err(|_| Error::msg("this device's member key is not a P-256 point"))?;
    let (cfg, exporter) = bykey::exporting_client(bykey::client(
        &own.tls_key()?,
        None,
        bykey::any_key(),
        cbb_core::alpn::PAIR,
        &tls::clock(),
    )?);
    sock.set_read_timeout(Some(step)).map_err(|e| Error::with("cannot set the timeout", e))?;
    let mut s = tls::Session::client(Arc::new(cfg), bykey::unsent_name())?;
    tls::handshake(&mut s, &sock, NO_HANDSHAKE)?;
    let member = bykey::peer_key(s.peer_certificates()).ok_or_else(|| Error::msg("the member showed no key"))?;
    if fp.is_some_and(|fp| cbb_core::records::Key::es256(member.to_vec()).hash() != fp) {
        return Err(Error::msg(format!(
            "{who} is not the window's member: its key is not the one the window announces"
        )));
    }
    let x = bykey::pairing_exporter(&s, &exporter)?;
    let mut stream = tls::Stream::new(s, sock);
    let mut info = Info::new(me.name, me.os, cbb_core::records::body::ROLE_MEMBER);
    info.caps = me.caps;
    // A computer that may be an admin offers its admin key with its proof
    // over this session: the root keeps it, and cbb admin there makes it
    // an admin later. One installed without root never is (D-79), nor one
    // in a container without its user's CBB_KEYS_IN_FILE=yes.
    if me.caps & cbb_core::records::body::CAP_ADMIN != 0 && crate::admin::keys_allowed().is_ok() {
        let admin = match own.admin.clone() {
            Some(k) => k,
            None => own.make(dir, crate::own::Which::Admin)?,
        };
        info.admin_pop = Some(cbb_core::join::sign_admin_pop(&*admin, &x)?.to_vec());
        info.admin = Some(admin.public());
    }
    let mut attempts = JoinerAttempts::default();
    let j = Joiner {
        attempts: &mut attempts,
        info,
        invitation,
        joining: Joining::Ordinary,
        own: point,
        member,
        exporter: x,
    };
    let now = || crate::uptime::wall_ms().max(0) as u64;
    let got = join::joiner(&mut stream, j, &now, &mut |a| {
        before(a)?;
        crate::set::save(dir, &a.set, &local)
    });
    // A member with no window open ends the connection at once.
    got.map_err(|e| {
        let eof = e.find::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof);
        if eof {
            e.context(format!("the pairing window is closed at {who}, or none was open: run cbb pair there, then join"))
        } else {
            e
        }
    })
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::{Mutex, mpsc};

    use super::*;

    #[test]
    fn a_computer_joins_at_home_and_keeps_the_group() {
        let desk = crate::admitting::tests_support::root_mesh("joining");
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let d2 = desk.clone();
        let (open, digits) =
            crate::admitting::home_window(crate::admitting::home_window_ms(), Duration::from_secs(300));
        let id = open.invitation.id;
        let open = Mutex::new(open);
        desk.on_pair(Some(Box::new(move |sock, s, x| {
            let got = crate::admitting::at_home(&d2, sock, s, x, &mut open.lock().unwrap());
            let _ = tx.lock().unwrap().send(got.is_ok());
        })));
        let d3 = desk.clone();
        std::thread::spawn(move || {
            for sock in ln.incoming().take(4).flatten() {
                let _ = d3.accept_port(sock);
            }
        });
        let dir = std::env::temp_dir().join(format!("cbb-joining-laptop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = Me { name: "laptop", os: 1, caps: 0 };
        // Wrong digits: refused, nothing kept, and the window stays open.
        let wrong = if digits == "000000" { "000001" } else { "000000" };
        let e = at_home(&dir, addr, &me, Invitation::typed(id, wrong).unwrap(), None).err().unwrap();
        assert!(e.message().contains("not the window's"), "{e:?}");
        assert!(!rx.recv_timeout(Duration::from_secs(10)).unwrap());
        assert!(crate::set::load(&dir, &crate::set::local_key(&dir).unwrap()).unwrap().is_none());
        // Another key than the window announces: refused before CPace.
        let typed = || Invitation::typed(id, &digits).unwrap();
        let e = at_home(&dir, addr, &me, typed(), Some(KeyHash([7; 32]))).err().unwrap();
        assert!(e.message().contains("is not the window's member"), "{e:?}");
        assert!(!rx.recv_timeout(Duration::from_secs(10)).unwrap(), "the member heard nothing");
        let fp = desk.own().hash();
        let a = at_home(&dir, addr, &me, typed(), Some(fp)).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap());
        let local = crate::set::local_key(&dir).unwrap();
        let kept = crate::set::load(&dir, &local).unwrap().unwrap();
        assert_eq!(kept.digest(), a.set.digest());
        let own = Own::load(&dir).unwrap();
        assert!(kept.state().device_by_key(&own.hash()).is_some());
        // Joined once, it does not join again.
        assert!(at_home(&dir, addr, &me, typed(), None).is_err());
        desk.close();
    }
}
