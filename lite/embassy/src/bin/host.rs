// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! esp32-on-linux: the ESP32 firmware's network code on Linux, so it can be
//! tested without the board. embassy-net runs over a TAP interface with a
//! fixed address instead of the chip's Wi-Fi and DHCP, and the device joins
//! a group by the phone as the board's `pair` does:
//!
//! ```text
//! esp32-on-linux [-debug] [-tap tap0] [-addr 192.168.69.2/24] [-name NAME] -identity FILE
//! ```
//!
//! The TAP interface must exist and be up, with an address of the same
//! network on the Linux side (`ip tuntap add tap0 mode tap`).

use std::net::Ipv4Addr;
use std::process::exit;
use std::sync::Arc;
use std::time::SystemTime;

use cbb_core::error::{self, Context, Error, Result};
use cbb_core::identity::Identity;
use cbb_core::tls::Clock;
use cbb_core::tls::rustls::pki_types::UnixTime;
use cbb_core::tls::rustls::time_provider::TimeProvider;
use cbb_embassy::pair::{Pairing, Saver};
use embassy_executor::Spawner;
use embassy_net::{Ipv4Cidr, Runner, StackResources, StaticConfigV4};
use embassy_net_tuntap::TunTapDevice;
use static_cell::StaticCell;

struct Args {
    tap: String,
    addr: Ipv4Cidr,
    name: String,
    identity: String,
}

const USAGE: &str = "usage: esp32-on-linux [-debug] [-tap tap0] [-addr 192.168.69.2/24] [-name NAME] -identity FILE";

fn args() -> Result<Args> {
    let mut a = Args {
        tap: "tap0".into(),
        addr: Ipv4Cidr::new(Ipv4Addr::new(192, 168, 69, 2), 24),
        name: "embassy".into(),
        identity: String::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "-debug" {
            error::set_show_details(true);
            continue;
        }
        let value = it.next().ok_or_else(|| Error::msg(USAGE))?;
        match flag.as_str() {
            "-tap" => a.tap = value,
            "-addr" => {
                a.addr = cidr(&value)
                    .ok_or_else(|| Error::msg("-addr takes an IPv4 address and prefix, such as 192.168.69.2/24"))?
            }
            "-name" => a.name = value,
            "-identity" => a.identity = value,
            _ => return Err(Error::msg(USAGE)),
        }
    }
    if a.identity.is_empty() {
        return Err(Error::msg(USAGE));
    }
    Ok(a)
}

fn cidr(s: &str) -> Option<Ipv4Cidr> {
    let (addr, len) = s.split_once('/')?;
    let len: u8 = len.parse().ok().filter(|l| *l <= 32)?;
    Some(Ipv4Cidr::new(addr.parse().ok()?, len))
}

#[derive(Debug)]
struct SystemClock;

impl TimeProvider for SystemClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).ok()?))
    }
}

/// Writes the identity to the file, as the board writes it to flash.
struct File(String);

impl Saver for File {
    async fn save(&mut self, id: &Identity) -> bool {
        match id.to_file().and_then(|b| std::fs::write(&self.0, b).context("cannot write the identity")) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("esp32-on-linux: {}", e.for_user());
                false
            }
        }
    }
}

#[embassy_executor::task]
async fn run_stack(mut runner: Runner<'static, TunTapDevice>) {
    runner.run().await
}

async fn join(spawner: Spawner, a: Args) -> Result<Identity> {
    let device = TunTapDevice::new(&a.tap).context("cannot open the TAP interface")?;
    let config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: a.addr,
        gateway: None,
        dns_servers: Default::default(),
    });
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).context("cannot seed the network stack")?;
    static RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    let (stack, runner) =
        embassy_net::new(device, config, RESOURCES.init(StackResources::new()), u64::from_le_bytes(seed));
    spawner.spawn(run_stack(runner).map_err(|_| Error::msg("cannot start the network task"))?);
    stack.wait_config_up().await;

    let pairing = Pairing::new(stack, &a.name)?;
    println!("Or paste this into the app: {}", pairing.text);
    let clock: Clock = Arc::new(SystemClock);
    pairing.run(stack, &clock, &mut File(a.identity), |m| eprintln!("esp32-on-linux: {m}")).await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let res = match args() {
        Ok(a) => join(spawner, a).await,
        Err(e) => Err(e),
    };
    match res {
        Ok(id) => {
            println!("Joined the group {} as {}", id.tag(), id.id);
            exit(0)
        }
        Err(e) => {
            eprintln!("esp32-on-linux: {}", e.for_user());
            exit(1)
        }
    }
}
