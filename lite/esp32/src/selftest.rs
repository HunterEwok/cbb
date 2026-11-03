// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Both ends of a pairing connection in memory: two devices make their keys
//! and self-signed certificates, run the TLS 1.3 handshake of
//! docs/protocol.md through the core's sans-I/O sessions, pass a message and
//! agree on the pairing's exporter, with the time each step takes.

use alloc::sync::Arc;
use alloc::vec::Vec;

use cbb_core::certs::{DeviceId, self_signed};
use cbb_core::error::{Error, Result};
use cbb_core::identity::{new_key, signing_key};
use cbb_core::tls::{Session, pair_client, pair_server, server_name};
use esp_hal::time::Instant;

use crate::clock;
use crate::println;

fn step(name: &str, start: Instant) {
    println!("cbb-esp32:   {name}: {} ms", start.elapsed().as_millis());
}

fn device() -> Result<(Vec<u8>, Vec<u8>)> {
    let key = new_key()?;
    let cert = self_signed(&DeviceId::random(), &signing_key(&key)?)?;
    Ok((cert, key))
}

/// Moves the bytes between the two sessions until neither has any to send.
fn shuttle(a: &mut Session, b: &mut Session) -> Result<()> {
    loop {
        let (x, y) = (a.take_outgoing(), b.take_outgoing());
        if x.is_empty() && y.is_empty() {
            return Ok(());
        }
        b.feed(&x)?;
        a.feed(&y)?;
    }
}

pub fn run() -> Result<()> {
    let clock = clock::fixed();
    let t = Instant::now();
    let ((jc, jk), (mc, mk)) = (device()?, device()?);
    step("two keys and certificates", t);

    let t = Instant::now();
    let (scfg, sx) = pair_server(&jc, &jk, &clock)?;
    let (ccfg, cx) = pair_client(&mc, &mk, &clock)?;
    let mut client = Session::client(Arc::new(ccfg), server_name(None))?;
    let mut server = Session::server(Arc::new(scfg))?;
    shuttle(&mut client, &mut server)?;
    if client.is_handshaking() || server.is_handshaking() {
        return Err(Error::msg("the handshake did not finish"));
    }
    step("TLS 1.3 handshake", t);

    let t = Instant::now();
    client.write(b"hello from the chip")?;
    shuttle(&mut client, &mut server)?;
    let mut buf = [0u8; 64];
    let n = server.read(&mut buf);
    if &buf[..n] != b"hello from the chip" {
        return Err(Error::msg("the message did not arrive"));
    }
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    cx.export(b"EXPORTER-cbb-test", b"", &mut a)?;
    sx.export(b"EXPORTER-cbb-test", b"", &mut b)?;
    if a != b {
        return Err(Error::msg("the two ends export different keys"));
    }
    step("a message and the exporter", t);
    Ok(())
}
