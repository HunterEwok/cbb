// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A computer joins a group at home (`cbb pair`, format section 8): it
//! dials a member that has a pairing window open (`cbb-pair/3`), both
//! persons check the code, and it keeps the set the member's Welcome
//! brought before it says so, as the group's records of 0.6
//! (`set::save`). Its member key is made on first use (`own.rs`).

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cbb_core::join::info::Info;
use cbb_core::join::invitation::JoinerAttempts;
use cbb_core::join::session::Admitted;
use cbb_core::join::welcome::Joining;
use cbb_core::tls::bykey;

use crate::error::{Error, Result};
use crate::join::{self, Ask, Joiner};
use crate::own::Own;
use crate::tls;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the joiner waits for each step: the persons read the code.
const STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// What a computer says of itself when it joins.
pub struct Me<'a> {
    pub name: &'a str,
    pub os: u64,
    pub caps: u64,
}

/// Joins the group of the member at addr, at home: `ask` shows the code
/// and gives the person's answer. The set is kept in dir before the
/// member hears it was; an error when this device is in a group already.
pub fn at_home(dir: &Path, addr: SocketAddr, me: &Me<'_>, ask: Ask<'_>) -> Result<Box<Admitted>> {
    let local = crate::set::local_key(dir)?;
    if crate::set::load(dir, &local)?.is_some() {
        return Err(Error::msg("this device is in a group already: leave it first (cbb leave)"));
    }
    let own = Own::load(dir)?;
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
    let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| Error::with(format!("cannot reach {addr}"), e))?;
    sock.set_read_timeout(Some(STEP_TIMEOUT)).map_err(|e| Error::with("cannot set the timeout", e))?;
    let mut s = tls::Session::client(Arc::new(cfg), bykey::unsent_name())?;
    tls::handshake(&mut s, &sock, "the handshake with the member failed")?;
    let member = bykey::peer_key(s.peer_certificates()).ok_or_else(|| Error::msg("the member showed no key"))?;
    let x = bykey::pairing_exporter(&s, &exporter)?;
    let mut stream = tls::Stream::new(s, sock);
    let mut info = Info::new(me.name, me.os, cbb_core::records::body::ROLE_MEMBER);
    info.caps = me.caps;
    let mut attempts = JoinerAttempts::default();
    let j = Joiner {
        attempts: &mut attempts,
        info,
        invitation: None,
        joining: Joining::Ordinary,
        own: point,
        member,
        exporter: x,
    };
    let now = || crate::uptime::wall_ms().max(0) as u64;
    join::joiner(&mut stream, j, ask, &now, &mut |a| crate::set::save(dir, &a.set, &local))
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
        desk.on_pair(Some(Box::new(move |sock, s, x| {
            let _ = tx.lock().unwrap().send(crate::admitting::at_home(&d2, sock, s, x, &mut |_| true).is_ok());
        })));
        let d3 = desk.clone();
        std::thread::spawn(move || {
            let (sock, _) = ln.accept().unwrap();
            let _ = d3.accept_port(sock);
        });
        let dir = std::env::temp_dir().join(format!("cbb-joining-laptop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = Me { name: "laptop", os: 1, caps: 0 };
        let a = at_home(&dir, addr, &me, &mut |_| true).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap());
        let local = crate::set::local_key(&dir).unwrap();
        let kept = crate::set::load(&dir, &local).unwrap().unwrap();
        assert_eq!(kept.digest(), a.set.digest());
        let own = Own::load(&dir).unwrap();
        assert!(kept.state().device_by_key(&own.hash()).is_some());
        // Joined once, it does not join again.
        assert!(at_home(&dir, addr, &me, &mut |_| true).is_err());
        desk.close();
    }
}
