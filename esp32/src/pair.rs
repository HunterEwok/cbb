// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining a group by the phone, with the pairing of cbb_embassy::pair in
//! a task: the identity goes to main, which saves it in flash before the
//! phone hears that the pairing worked.

use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

use cbb_core::error::{Error, Result};
use cbb_core::identity::Identity;
use cbb_embassy::pair::{Pairing, Saver};
use embassy_executor::Spawner;
use embassy_net::Stack;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

use crate::clock;
use crate::println;

/// A pairing's new identity, for main to save; it answers on SAVED.
pub static JOINED: Signal<CriticalSectionRawMutex, Identity> = Signal::new();
/// Whether main saved the identity, which the phone hears.
pub static SAVED: Signal<CriticalSectionRawMutex, bool> = Signal::new();
static BUSY: AtomicBool = AtomicBool::new(false);

/// Starts listening for the phone and returns the QR code's text.
pub fn start(spawner: Spawner, stack: Stack<'static>, name: &str) -> Result<String> {
    if stack.config_v4().is_none() {
        return Err(Error::msg("the board has no address yet: set the Wi-Fi network up first (see status)"));
    }
    if BUSY.swap(true, Ordering::AcqRel) {
        return Err(Error::msg("the board is already waiting for a phone"));
    }
    let started = Pairing::new(stack, name).and_then(|p| {
        let text = p.text.clone();
        spawner.spawn(listen(stack, p).map_err(|_| Error::msg("cannot start the pairing task"))?);
        Ok(text)
    });
    if started.is_err() {
        BUSY.store(false, Ordering::Release);
    }
    started
}

/// Hands the identity to main, which owns the flash.
struct Flash;

impl Saver for Flash {
    async fn save(&mut self, id: &Identity) -> bool {
        JOINED.signal(id.clone());
        SAVED.wait().await
    }
}

#[embassy_executor::task]
async fn listen(stack: Stack<'static>, pairing: Pairing) {
    match pairing.run(stack, &clock::fixed(), &mut Flash, |m| println!("cbb-esp32: {m}")).await {
        Ok(id) => println!("cbb-esp32: joined the group {} as {}", id.tag(), id.id),
        Err(e) => println!("cbb-esp32: {}", e.for_user()),
    }
    BUSY.store(false, Ordering::Release);
}
