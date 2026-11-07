// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining a group over the network: the TLS connection around the
//! exchange of cbb_core::pair, either listening for the phone that scanned
//! this device's QR code or dialing a Linux member's open pairing window.

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use cbb_core::pair::*;

use crate::error::{Context, Error, Result, Wrap};
use crate::identity::Identity;
use crate::tls;
use crate::wire;

/// What stores a join's result: the records that lead to the group's
/// roots, then the identity, so the identity never trusts roots its records
/// do not name.
pub type Save = dyn Fn(&Identity, &[crate::records::Record], &[crate::records::ClaimTime]) -> Result<()>;

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a listening join waits.
pub const LIFETIME: Duration = Duration::from_secs(5 * 60);

/// Runs the joining side over a connection a member dialed to this joiner,
/// which showed its QR code. The member confirms first, so a device that
/// does not know the code learns nothing.
pub fn accept(j: &Joiner, sock: TcpStream, code: &str, save: &Save) -> Result<Identity> {
    let (cfg, exporter) = match j.external_key() {
        Some(k) => tls::pair_server_external(&j.cert, k.clone(), &tls::clock())?,
        None => tls::pair_server(&j.cert, &j.key, &tls::clock())?,
    };
    let session = tls::Session::server(Arc::new(cfg))?;
    run(j, tls::Stream::new(session, sock), &exporter, code, true, save)
}

/// Runs the joining side over a connection to a member's open pairing
/// window, with the code the user typed.
pub fn join(j: &Joiner, sock: TcpStream, code: &str, save: &Save) -> Result<Identity> {
    let (cfg, exporter) = match j.external_key() {
        Some(k) => tls::pair_client_external(&j.cert, k.clone(), &tls::clock())?,
        None => tls::pair_client(&j.cert, &j.key, &tls::clock())?,
    };
    let session = tls::Session::client(Arc::new(cfg), tls::server_name(None))?;
    run(j, tls::Stream::new(session, sock), &exporter, code, false, save)
}

fn run(
    j: &Joiner,
    mut tc: tls::Stream,
    exporter: &tls::Exporter,
    code: &str,
    member_first: bool,
    save: &Save,
) -> Result<Identity> {
    normalize_code(code)?;
    tc.sock.set_read_timeout(Some(ATTEMPT_TIMEOUT)).context("the connection broke")?;
    tc.sock.set_write_timeout(Some(ATTEMPT_TIMEOUT)).context("the connection broke")?;
    tls::handshake(&mut tc.session, &tc.sock, "the TLS handshake failed")?;
    if tc.session.alpn_protocol() != Some(tls::PAIR_PROTOCOL) {
        return Err(Error::msg("the device does not offer pairing"));
    }
    let member_der = tc
        .session
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.to_vec())
        .ok_or_else(|| Error::msg("the device does not offer pairing"))?;
    let mut sid = [0u8; 32];
    exporter.export(EXPORTER_LABEL, &[], &mut sid).wrap("cannot bind the pairing to TLS")?;
    let id = exchange(j, &mut tc, code, &member_der, &sid, member_first, save)?;
    tc.close();
    Ok(id)
}

/// Runs the frames of the exchange over a TLS stream.
fn exchange(
    j: &Joiner,
    rw: &mut (impl std::io::Read + Write),
    code: &str,
    member_der: &[u8],
    sid: &[u8],
    member_first: bool,
    save: &Save,
) -> Result<Identity> {
    let send = |rw: &mut dyn Write, f: &[u8]| -> Result<()> {
        rw.write_all(f).context("the connection broke")?;
        rw.flush().context("the connection broke")
    };
    let (mut ex, first) = j.start(code, member_der, sid, member_first)?;
    send(rw, &first)?;
    let confirm = match ex.reply(&wire::read_frame(rw, MAX_FRAME)?) {
        Ok(f) => f,
        Err(Failure { error, send: reply }) => {
            if let Some(f) = reply {
                let _ = send(rw, &f);
            }
            return Err(error);
        }
    };
    send(rw, &confirm)?;
    let res = ex
        .welcome(&wire::read_frame(rw, MAX_FRAME)?, crate::uptime::wall_ms())
        .and_then(|id| save(&id, &ex.records(), &ex.claim_times()).map(|_| id));
    let _ = send(rw, &done(res.is_ok()));
    res
}

/// Reports whether an address may reach the member port: what mDNS would
/// publish (private IPv4, unique-local and link-local IPv6) or loopback.
pub fn home_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return home_address(IpAddr::V4(v4));
            }
            a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The addresses for the QR code: those mDNS would publish, IPv4 first,
/// without link-local ones, at most four.
pub fn qr_addresses(port: u16) -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if iface.is_loopback() || !crate::interfaces::allowed(&iface.name) {
            continue;
        }
        match iface.ip() {
            IpAddr::V4(a) if a.is_private() => v4.push(SocketAddr::new(IpAddr::V4(a), port).to_string()),
            IpAddr::V6(a) if (a.segments()[0] & 0xfe00) == 0xfc00 => {
                v6.push(SocketAddr::new(IpAddr::V6(a), port).to_string())
            }
            _ => {}
        }
    }
    v4.extend(v6);
    v4.dedup();
    v4.truncate(4);
    v4
}

/// Listens for a member that dials this joiner, for up to LIFETIME. It
/// calls shown with the QR code's text once it listens, takes one attempt
/// at a time, gives up after the third wrong code, and returns the new
/// identity, which save stored.
#[allow(clippy::too_many_arguments)]
pub fn listen(
    joiner: &Joiner,
    ln: TcpListener,
    addrs: Option<Vec<String>>,
    code: &str,
    wait: Duration,
    shown: &dyn Fn(&str),
    save: &Save,
    log: &dyn Fn(&str),
) -> Result<Identity> {
    let port = ln.local_addr().context("cannot listen")?.port();
    let addrs = addrs.unwrap_or_else(|| qr_addresses(port));
    if addrs.is_empty() {
        return Err(Error::msg(
            "this device has no address on the home network; connect it to the network, or use pair -code",
        ));
    }
    shown(&join_qr(code, &addrs, &joiner.fingerprint()));
    ln.set_nonblocking(true).context("cannot listen")?;
    let end = Instant::now() + wait;
    let mut failures = 0;
    while Instant::now() < end {
        let (sock, from) = match ln.accept() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(Error::with("cannot accept a connection", e)),
        };
        if !home_address(from.ip()) || !crate::interfaces::arrived(&sock) {
            continue;
        }
        let _ = sock.set_nonblocking(false);
        match accept(joiner, sock, code, save) {
            Ok(id) => return Ok(id),
            Err(e) => {
                log(&format!("cbb: a pairing attempt from {from} failed: {}", e.for_log()));
                if e.details().contains(Refusal::WrongCode.message()) {
                    failures += 1;
                    if failures >= MAX_FAILURES {
                        return Err(Error::with("the pairing failed", Refusal::TooMany));
                    }
                }
            }
        }
    }
    Err(Error::msg("no device joined this one in time; run join again"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::Cert;

    #[test]
    fn the_joiner_certificate() {
        let j = Joiner::new("router").unwrap();
        let c = Cert::parse(&j.cert).unwrap();
        assert_eq!(c.common_name.as_deref(), Some(j.id.as_str()));
        assert!(c.p256);
        assert!(c.signed_by(&c));
        assert_eq!(j.fingerprint().len(), 44);
        // rustls and the core's provider take the key and the certificate.
        tls::pair_server(&j.cert, &j.key, &tls::clock()).unwrap();
    }
}
