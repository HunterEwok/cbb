// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The board as a Bluetooth LE keyboard (docs/roadmap.md, item 25): HID
//! over GATT with trouble-host on esp-radio's controller, which shares the
//! radio with Wi-Fi. The ESP32-S3 has no classic Bluetooth, so a host must
//! take BLE keyboards: TVs, tablets, phones and computers do.
//!
//! The keyboard is discoverable only while the console's ble pair asks it
//! to be, for two minutes; the rest of the time it advertises without the
//! discoverable flag, so the hosts it is paired with find it again and no
//! other device lists it. A host that pairs outside those two minutes is
//! dropped, and the board types only on a host it is paired with. Pairing
//! is Just Works (the board has no display to show a code), as with any
//! keyboard without one. The bonds go to main, which saves them in flash.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use cbb_core::error::{Error, Result};
use embassy_futures::join::join;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use esp_hal::efuse::{self, InterfaceMacAddress};
use esp_hal::peripherals::BT;
use esp_radio::ble::controller::BleConnector;
use static_cell::StaticCell;
use trouble_host::prelude::*;

use self::gatt::Server;
use crate::println;
use crate::store::{Bond, MAX_BONDS};
use crate::usb::Typing;

/// What a host lists the keyboard as.
const NAME: &str = "CBB Nano ESP32";
/// How long ble pair makes the keyboard discoverable.
pub const VISIBLE_FOR: Duration = Duration::from_secs(120);

type Controller = ExternalController<BleConnector<'static>, 1>;
type Resources = HostResources<Controller, DefaultPacketPool, 1, 2, 1, MAX_BONDS>;

static STARTED: AtomicBool = AtomicBool::new(false);
/// Whether a host the keyboard is paired with is connected over an
/// encrypted link.
static CONNECTED: AtomicBool = AtomicBool::new(false);
/// Until when the keyboard is discoverable, in seconds since boot; 0 when
/// it is not.
static VISIBLE_UNTIL: AtomicU32 = AtomicU32::new(0);
/// Wakes the advertiser when ble pair asks for the keyboard to be found.
static VISIBLE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static TYPE: Channel<CriticalSectionRawMutex, Typing, 1> = Channel::new();
/// The bonds after a host paired, for main to save.
pub static BONDED: Signal<CriticalSectionRawMutex, Vec<Bond>> = Signal::new();

pub fn started() -> bool {
    STARTED.load(Ordering::Relaxed)
}

pub fn connected() -> bool {
    CONNECTED.load(Ordering::Relaxed)
}

/// The seconds the keyboard stays discoverable, if it is.
pub fn visible_for() -> Option<u64> {
    let until = u64::from(VISIBLE_UNTIL.load(Ordering::Relaxed));
    let now = Instant::now().as_secs();
    (until > now).then(|| until - now)
}

/// Makes the keyboard discoverable for VISIBLE_FOR.
pub fn make_visible() -> Result<()> {
    if !started() {
        return Err(Error::msg("the Bluetooth keyboard is off: type ble on first"));
    }
    VISIBLE_UNTIL.store((Instant::now() + VISIBLE_FOR).as_secs() as u32, Ordering::Relaxed);
    VISIBLE.signal(());
    Ok(())
}

/// Hands a text to the keyboard; false when it is still typing the last.
pub fn type_text(t: Typing) -> bool {
    TYPE.try_send(t).is_ok()
}

/// The GATT services. The battery and the device's information answer the
/// host by themselves, so their fields are never read.
#[allow(dead_code)]
mod gatt {
    use trouble_host::prelude::*;

    #[gatt_server]
    pub struct Server {
        pub hid: HidService,
        battery: BatteryService,
        device: DeviceInformation,
    }

    /// The HID service of HOGP (HID over GATT profile 1.0) for a keyboard.
    #[gatt_service(uuid = service::HUMAN_INTERFACE_DEVICE)]
    pub struct HidService {
        /// HID 1.11, no country code, may wake the host, normally connectable.
        #[characteristic(uuid = characteristic::HID_INFORMATION, read, value = [0x11, 0x01, 0x00, 0x03], permissions(encrypted))]
        pub info: [u8; 4],
        #[characteristic(uuid = characteristic::REPORT_MAP, read, value = cbb_core::keyboard::DESCRIPTOR, permissions(encrypted))]
        pub report_map: [u8; 63],
        #[characteristic(uuid = characteristic::HID_CONTROL_POINT, write_without_response, permissions(encrypted))]
        pub control: u8,
        /// 1 for the report protocol, 0 for the boot protocol.
        #[characteristic(uuid = characteristic::PROTOCOL_MODE, read, write_without_response, value = 1, permissions(encrypted))]
        pub protocol: u8,
        /// The keys, in the report protocol: the report without an ID, input.
        #[descriptor(uuid = descriptors::REPORT_REFERENCE, read = encrypted, value = [0u8, 1u8])]
        #[characteristic(uuid = characteristic::REPORT, read, notify, permissions(encrypted))]
        pub input: [u8; 8],
        /// The host's LEDs, output.
        #[descriptor(uuid = descriptors::REPORT_REFERENCE, read = encrypted, value = [0u8, 2u8])]
        #[characteristic(uuid = characteristic::REPORT, read, write, write_without_response, permissions(encrypted))]
        pub output: [u8; 1],
        /// The keys, in the boot protocol a BIOS asks for.
        #[characteristic(uuid = characteristic::BOOT_KEYBOARD_INPUT_REPORT, read, notify, permissions(encrypted))]
        pub boot_input: [u8; 8],
        #[characteristic(uuid = characteristic::BOOT_KEYBOARD_OUTPUT_REPORT, read, write, write_without_response, permissions(encrypted))]
        pub boot_output: [u8; 1],
    }

    /// Powered by USB: always full.
    #[gatt_service(uuid = service::BATTERY)]
    struct BatteryService {
        #[characteristic(uuid = characteristic::BATTERY_LEVEL, read, notify, value = 100, permissions(encrypted))]
        level: u8,
    }

    #[gatt_service(uuid = service::DEVICE_INFORMATION)]
    struct DeviceInformation {
        /// USB vendor IDs, Espressif's, the product ID of the USB keyboard,
        /// version 1.0.
        #[characteristic(uuid = characteristic::PNP_ID, read, value = [0x02, 0x3a, 0x30, 0x05, 0x40, 0x00, 0x01])]
        pnp: [u8; 7],
    }
}

/// Starts the keyboard with the hosts it is paired with.
pub fn start(spawner: embassy_executor::Spawner, bt: BT<'static>, bonds: Vec<Bond>) -> Result<()> {
    let connector = BleConnector::new(bt, Default::default()).map_err(|e| Error::with("cannot start Bluetooth", e))?;
    spawner.spawn(
        run(ExternalController::new(connector), bonds).map_err(|_| Error::msg("cannot start the Bluetooth task"))?,
    );
    STARTED.store(true, Ordering::Relaxed);
    Ok(())
}

/// The board's identity address: a static random address from the
/// Bluetooth MAC address in eFuse, the same after every restart, so the
/// hosts it is paired with know it again.
fn address() -> Address {
    let mac = efuse::interface_mac_address(InterfaceMacAddress::Bluetooth);
    let mut a = [0u8; 6];
    // The address goes least significant byte first; a static random
    // address has the top two bits set.
    for (i, b) in mac.as_bytes().iter().rev().enumerate() {
        a[i] = *b;
    }
    a[5] |= 0xc0;
    Address::random(a)
}

fn to_info(b: &Bond) -> BondInformation {
    let identity = Identity {
        addr: Address::new(AddrKind::new(b.kind), BdAddr::new(b.addr)),
        irk: b.irk.and_then(|k| IdentityResolvingKey::new(u128::from_le_bytes(k))),
    };
    let level = if b.authenticated { SecurityLevel::EncryptedAuthenticated } else { SecurityLevel::Encrypted };
    BondInformation::new(identity, LongTermKey::new(u128::from_le_bytes(b.ltk)), level, true)
}

fn from_info(b: &BondInformation) -> Bond {
    Bond {
        kind: b.identity.addr.kind.into_inner(),
        addr: b.identity.addr.addr.into_inner(),
        irk: b.identity.irk.map(|k| k.0.get().to_le_bytes()),
        ltk: b.ltk.0.to_le_bytes(),
        authenticated: b.security_level == SecurityLevel::EncryptedAuthenticated,
    }
}

#[embassy_executor::task]
async fn run(controller: Controller, mut bonds: Vec<Bond>) {
    static RESOURCES: StaticCell<Resources> = StaticCell::new();
    let address = address();
    let stack = trouble_host::new(controller, RESOURCES.init(Resources::new()))
        .set_random_address(address)
        .set_io_capabilities(IoCapabilities::NoInputNoOutput)
        .build();
    for b in &bonds {
        if stack.add_bond_information(to_info(b)).is_err() {
            println!("cbb-esp32: a saved Bluetooth pairing does not fit; pair that host again");
        }
    }
    let server = match Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: NAME,
        appearance: &appearance::human_interface_device::KEYBOARD,
    })) {
        Ok(s) => s,
        Err(e) => {
            println!("cbb-esp32: the Bluetooth keyboard did not start: {e:?}");
            return;
        }
    };
    println!("cbb-esp32: the Bluetooth keyboard is on, as {address}");
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();
    let host = async {
        loop {
            if let Err(e) = runner.run().await {
                println!("cbb-esp32: Bluetooth stopped ({e:?}); starting it again");
                Timer::after_secs(1).await;
            }
        }
    };
    let keyboard = async {
        loop {
            serve(&stack, &mut peripheral, &server, &mut bonds).await;
        }
    };
    join(host, keyboard).await;
}

/// Advertises until a host connects, serves it until it goes, and keeps a
/// new pairing.
async fn serve(
    stack: &Stack<'_, Controller, DefaultPacketPool>,
    peripheral: &mut Peripheral<'_, Controller, DefaultPacketPool>,
    server: &Server<'_>,
    bonds: &mut Vec<Bond>,
) {
    let visible = visible_for().is_some();
    if !visible {
        VISIBLE_UNTIL.store(0, Ordering::Relaxed);
        if bonds.is_empty() {
            // Nobody to wait for until ble pair.
            VISIBLE.wait().await;
            return;
        }
    }
    let mut adv = [0u8; 31];
    let flags = if visible { LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED } else { BR_EDR_NOT_SUPPORTED };
    let len = match AdStructure::encode_slice(
        &[
            AdStructure::Flags(flags),
            AdStructure::IncompleteServiceUuids16(&[service::HUMAN_INTERFACE_DEVICE.to_le_bytes()]),
            AdStructure::Unknown { ty: 0x19, data: &appearance::human_interface_device::KEYBOARD.to_le_bytes() },
            AdStructure::CompleteLocalName(NAME.as_bytes()),
        ],
        &mut adv,
    ) {
        Ok(len) => len,
        Err(e) => {
            println!("cbb-esp32: the Bluetooth advertisement does not fit: {e:?}");
            Timer::after_secs(60).await;
            return;
        }
    };
    let advertiser = match peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected { adv_data: &adv[..len], scan_data: &[] },
        )
        .await
    {
        Ok(a) => a,
        Err(e) => {
            println!("cbb-esp32: Bluetooth cannot advertise: {e:?}");
            Timer::after_secs(5).await;
            return;
        }
    };
    // A change of the discoverable flag starts the advertisement again.
    let change = async {
        match visible_for() {
            Some(s) => Timer::after_secs(s).await,
            None => VISIBLE.wait().await,
        }
    };
    let conn = match select(advertiser.accept(), change).await {
        Either::First(Ok(c)) => c,
        Either::First(Err(e)) => {
            println!("cbb-esp32: a Bluetooth host did not connect: {e:?}");
            return;
        }
        Either::Second(()) => return,
    };
    let conn = match conn.with_attribute_server(server) {
        Ok(c) => c,
        Err(e) => {
            println!("cbb-esp32: cannot serve the Bluetooth host: {e:?}");
            return;
        }
    };
    // Only while discoverable may a new host bond.
    let _ = conn.raw().set_bondable(visible_for().is_some());
    select(events(stack, &conn, bonds), keys(server, &conn)).await;
    CONNECTED.store(false, Ordering::Relaxed);
}

/// Answers the host's requests until it goes; marks the link trusted once
/// it is encrypted with a bond, and keeps a new one.
async fn events(
    stack: &Stack<'_, Controller, DefaultPacketPool>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    bonds: &mut Vec<Bond>,
) {
    loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { .. } => return,
            GattConnectionEvent::PairingComplete { bond: Some(bond), .. } => {
                if visible_for().is_none() {
                    println!("cbb-esp32: a Bluetooth host paired while the keyboard was not discoverable; dropped it");
                    let _ = stack.remove_bond_information(bond.identity);
                    conn.raw().disconnect();
                    continue;
                }
                let new = from_info(&bond);
                bonds.retain(|b| b.addr != new.addr || b.kind != new.kind);
                if bonds.len() == MAX_BONDS {
                    let old = bonds.remove(0);
                    let _ = stack.remove_bond_information(to_info(&old).identity);
                }
                bonds.push(new);
                BONDED.signal(bonds.clone());
                // Paired: no other host needs to find it now.
                VISIBLE_UNTIL.store(0, Ordering::Relaxed);
                CONNECTED.store(true, Ordering::Relaxed);
                println!("cbb-esp32: paired with the Bluetooth host {}", bond.identity.addr);
            }
            GattConnectionEvent::PairingComplete { bond: None, .. } => {
                println!(
                    "cbb-esp32: a Bluetooth host connected without pairing; the keyboard types only on a paired host"
                );
            }
            GattConnectionEvent::Encrypted { bond: Some(_), .. } => {
                CONNECTED.store(true, Ordering::Relaxed);
                println!("cbb-esp32: a paired Bluetooth host connected");
            }
            GattConnectionEvent::PairingFailed(e) => {
                println!("cbb-esp32: pairing with a Bluetooth host failed: {e:?}");
            }
            GattConnectionEvent::BondLost => {
                println!("cbb-esp32: a Bluetooth host forgot the pairing; type ble pair, then pair it again");
            }
            GattConnectionEvent::Gatt { event } => match event.accept() {
                Ok(reply) => reply.send().await,
                Err(e) => println!("cbb-esp32: cannot answer the Bluetooth host: {e:?}"),
            },
            _ => {}
        }
    }
}

/// Types what the console hands over, as long as the host is connected.
async fn keys(server: &Server<'_>, conn: &GattConnection<'_, '_, DefaultPacketPool>) {
    loop {
        let t = TYPE.receive().await;
        if !connected() {
            println!("cbb-esp32: the Bluetooth host is not paired yet; nothing was typed");
            continue;
        }
        let input = if server.get(&server.hid.protocol) == Ok(0) { server.hid.boot_input } else { server.hid.input };
        let mut typed = true;
        for r in &t.reports {
            if input.notify(conn, r, false).await.is_err() {
                typed = false;
                break;
            }
            Timer::after_millis(t.gap_ms).await;
        }
        if typed {
            println!("cbb-esp32: typed");
        } else {
            let _ = input.notify(conn, &cbb_core::keyboard::RELEASE, false).await;
            println!("cbb-esp32: the Bluetooth host stopped taking keys; nothing more was typed");
        }
    }
}
