// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A device's registration with the relay (`cbb-relay/3`): the TLS
//! connections taken and counted by their source, each registration held
//! while its connection lasts; `register3` checks what the device shows.

use std::io::Read;
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::Arc;

use super::server::{Inner, Member, spawn};
use super::wire;
use crate::error::{Error, Result};

/// The IP address of a connection's remote end, IPv4 when it is mapped.
pub fn addr_of(c: &TcpStream) -> Option<IpAddr> {
    c.peer_addr().ok().map(|a| match a.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        a => a,
    })
}

impl Inner {
    /// Takes the devices' TLS connections.
    pub(super) fn accept_registrations(self: Arc<Self>, ln: TcpListener) {
        let mut failed = super::server::AcceptErrors::default();
        for conn in ln.incoming() {
            if self.stopping() {
                return;
            }
            let conn = match conn {
                Ok(c) => c,
                Err(e) => {
                    failed.note(&self.cfg.log, "devices' connections", &e);
                    continue;
                }
            };
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
        let r = self.register(&raw);
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

    /// Runs a registration's setup: the TLS handshake, then the
    /// registration of 0.6.
    fn register(
        self: &Arc<Self>,
        raw: &TcpStream,
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
        if s.conn.alpn_protocol() != Some(super::wire3::PROTOCOL) {
            return Err(Error::msg("relay: the device does not speak the registration protocol"));
        }
        self.register3(raw, s)
    }
}
