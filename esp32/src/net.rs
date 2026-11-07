// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Wi-Fi: joins the network the console set, takes an address by DHCP and
//! joins again whenever the connection drops or the network changes.

use alloc::format;
use alloc::string::String;
use core::cell::RefCell;

use cbb_core::error::{Context, Error, Result};
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::{Ipv4Cidr, Runner, Stack, StackResources};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use esp_hal::peripherals::WIFI;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{AuthenticationMethodConfig, Config, ControllerConfig, Interface, WifiController};
use static_cell::StaticCell;

use crate::println;
use crate::store::Wifi;

/// How long to wait before joining again after a failure.
const RETRY: Duration = Duration::from_secs(5);

enum State {
    Off,
    Joining(String),
    Joined(String),
    Failed(String, Error),
}

static WANTED: Signal<CriticalSectionRawMutex, Option<Wifi>> = Signal::new();
static STATE: Mutex<CriticalSectionRawMutex, RefCell<State>> = Mutex::new(RefCell::new(State::Off));
static ADDRESS: Mutex<CriticalSectionRawMutex, RefCell<Option<Ipv4Cidr>>> = Mutex::new(RefCell::new(None));

/// Starts Wi-Fi and the network stack, joining wifi if one is set.
pub fn start(spawner: Spawner, device: WIFI<'static>, wifi: Option<Wifi>) -> Result<Stack<'static>> {
    let controller = WifiController::new(device, ControllerConfig::default()).context("cannot start Wi-Fi")?;
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).context("cannot seed the network stack")?;
    static RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(
        Interface::station(),
        embassy_net::Config::dhcpv4(Default::default()),
        RESOURCES.init(StackResources::new()),
        u64::from_le_bytes(seed),
    );
    spawner.spawn(connection(controller, wifi).map_err(|_| Error::msg("cannot start the Wi-Fi task"))?);
    spawner.spawn(run_stack(runner).map_err(|_| Error::msg("cannot start the network task"))?);
    spawner.spawn(address(stack).map_err(|_| Error::msg("cannot start the address task"))?);
    Ok(stack)
}

/// Joins wifi instead of the network before, or leaves it with None.
pub fn want(wifi: Option<Wifi>) {
    WANTED.signal(wifi);
}

/// How the network is doing, in a line for the console.
pub fn status() -> String {
    let address = ADDRESS.lock(|a| *a.borrow());
    STATE.lock(|s| match &*s.borrow() {
        State::Off => "off (no Wi-Fi network set)".into(),
        State::Joining(ssid) => format!("joining {ssid}"),
        State::Joined(ssid) => match address {
            Some(a) => format!("joined {ssid}, address {a}"),
            None => format!("joined {ssid}, waiting for an address (DHCP)"),
        },
        State::Failed(ssid, e) => format!("cannot join {ssid}: {}; trying again", e.for_user()),
    })
}

fn set(state: State) {
    match &state {
        State::Joined(ssid) => println!("cbb-esp32: joined {ssid}"),
        State::Failed(ssid, e) => println!("cbb-esp32: cannot join {ssid}: {}", e.for_user()),
        _ => {}
    }
    STATE.lock(|s| *s.borrow_mut() = state);
}

fn station(wifi: &Wifi) -> Result<Config> {
    let auth = if wifi.password.is_empty() {
        AuthenticationMethodConfig::Open
    } else {
        AuthenticationMethodConfig::Wpa2Personal(wifi.password.as_str().try_into().context("the password is too long")?)
    };
    let ssid = wifi.ssid.as_str().try_into().context("the network name is too long")?;
    Ok(Config::Station(StationConfig::default().with_ssid(ssid).with_authentication(auth)))
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>, mut wanted: Option<Wifi>) {
    loop {
        let Some(wifi) = wanted.clone() else {
            set(State::Off);
            wanted = WANTED.wait().await;
            continue;
        };
        set(State::Joining(wifi.ssid.clone()));
        if let Err(e) = station(&wifi).and_then(|c| controller.set_config(&c).context("cannot set Wi-Fi up")) {
            set(State::Failed(wifi.ssid.clone(), e));
            wanted = WANTED.wait().await;
            continue;
        }
        match select(controller.connect_async(), WANTED.wait()).await {
            Either::First(Ok(_)) => {
                set(State::Joined(wifi.ssid.clone()));
                if let Either::Second(next) = select(controller.wait_for_disconnect_async(), WANTED.wait()).await {
                    wanted = next;
                    let _ = controller.disconnect_async().await;
                } else {
                    println!("cbb-esp32: lost {}", wifi.ssid);
                }
            }
            Either::First(Err(e)) => {
                set(State::Failed(wifi.ssid.clone(), Error::with("the network did not let the board in", e)));
                if let Either::Second(next) = select(Timer::after(RETRY), WANTED.wait()).await {
                    wanted = next;
                }
            }
            Either::Second(next) => {
                wanted = next;
                let _ = controller.disconnect_async().await;
            }
        }
    }
}

#[embassy_executor::task]
async fn run_stack(mut runner: Runner<'static, Interface>) {
    runner.run().await
}

/// Keeps the address that DHCP gave for status, and logs it.
#[embassy_executor::task]
async fn address(stack: Stack<'static>) {
    loop {
        stack.wait_config_up().await;
        let a = stack.config_v4().map(|c| c.address);
        if let Some(a) = a {
            println!("cbb-esp32: address {a}");
        }
        ADDRESS.lock(|s| *s.borrow_mut() = a);
        stack.wait_config_down().await;
        ADDRESS.lock(|s| *s.borrow_mut() = None);
    }
}
