// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The board's USB port as a keyboard (docs/roadmap.md, item 25): a USB
//! device of two functions on the chip's OTG controller, a boot keyboard
//! that types a text and a serial port (CDC-ACM) for the console.
//!
//! The Nano ESP32's USB-C port has the chip's only USB PHY, which either
//! the USB serial (USB-Serial-JTAG: the console, the log and espflash's
//! automatic reset) or the OTG controller has. So the keyboard is a mode,
//! saved in the settings and taken at boot: in it the console is the
//! serial port beside the keyboard, and espflash needs the console's flash
//! command, or B1 shorted to GND while reset is pressed, to reach the ROM's
//! download mode.

use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use cbb_core::error::{Error, Result};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::pipe::Pipe;
use embassy_time::Timer;
use embassy_usb::class::cdc_acm::{self, CdcAcmClass};
use embassy_usb::class::hid::{self, HidBootProtocol, HidProtocolMode, HidSubclass, HidWriter, RequestHandler};
use embassy_usb::control::OutResponse;
use embassy_usb::{Builder, UsbDevice};
use esp_hal::peripherals::{GPIO19, GPIO20, LPWR, USB_FS};
use esp_hal::usb::otg::Usb;
use esp_hal::usb::otg::embassy_usb_device::{Config, Driver};
use static_cell::StaticCell;

use crate::println;

/// Espressif's vendor ID with the product ID its TinyUSB stack gives a
/// device of a serial port and a HID function.
const VID: u16 = 0x303a;
const PID: u16 = 0x4005;

/// Whether the console is the serial port beside the keyboard.
static ON_OTG: AtomicBool = AtomicBool::new(false);
/// What the console writes, until the serial port takes it; what does not
/// fit while no terminal reads is dropped.
static OUT: Pipe<CriticalSectionRawMutex, 2048> = Pipe::new();
/// What the terminal types, for the console.
pub static IN: Pipe<CriticalSectionRawMutex, 256> = Pipe::new();

/// A text to type, as the reports that type it, and the time between two.
pub struct Typing {
    pub reports: Vec<[u8; 8]>,
    pub gap_ms: u64,
}

static TYPE: Channel<CriticalSectionRawMutex, Typing, 1> = Channel::new();

pub fn console_on_otg() -> bool {
    ON_OTG.load(Ordering::Relaxed)
}

/// Queues text for the serial port; a new line goes as CR LF, which every
/// terminal shows as the start of a line.
pub fn console_write(args: fmt::Arguments) {
    struct Sink;
    impl Write for Sink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            for (i, part) in s.split('\n').enumerate() {
                if i > 0 {
                    let _ = OUT.try_write(b"\r\n");
                }
                let _ = OUT.try_write(part.as_bytes());
            }
            Ok(())
        }
    }
    let _ = Sink.write_fmt(args);
}

/// Hands a text to the keyboard; false when it is still typing the last.
pub fn type_text(t: Typing) -> bool {
    TYPE.try_send(t).is_ok()
}

/// Takes the boot protocol that a BIOS or a KVM asks for: its reports are
/// the same eight bytes.
struct Protocol(HidProtocolMode);

impl RequestHandler for Protocol {
    fn get_protocol(&self) -> HidProtocolMode {
        self.0
    }

    fn set_protocol(&mut self, protocol: HidProtocolMode) -> OutResponse {
        self.0 = protocol;
        OutResponse::Accepted
    }
}

/// Makes the USB port the keyboard and the console's serial port, and
/// starts their tasks.
pub fn start(
    spawner: embassy_executor::Spawner,
    usb: USB_FS<'static>,
    dp: GPIO20<'static>,
    dm: GPIO19<'static>,
) -> Result<()> {
    static EP_OUT: StaticCell<[u8; 1024]> = StaticCell::new();
    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL: StaticCell<[u8; 64]> = StaticCell::new();
    static HID_STATE: StaticCell<hid::State> = StaticCell::new();
    static CDC_STATE: StaticCell<cdc_acm::State> = StaticCell::new();
    static PROTOCOL: StaticCell<Protocol> = StaticCell::new();

    let driver = Driver::new(Usb::new_fs(usb, dp, dm), EP_OUT.init([0; 1024]), Config::default());
    let mut config = embassy_usb::Config::new(VID, PID);
    config.manufacturer = Some("cbb");
    config.product = Some("cbb keyboard");
    config.max_power = 100;
    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        &mut [],
        CONTROL.init([0; 64]),
    );
    let keyboard = HidWriter::<_, 8>::new(
        &mut builder,
        HID_STATE.init(hid::State::new()),
        hid::Config {
            report_descriptor: &cbb_core::keyboard::DESCRIPTOR,
            request_handler: Some(PROTOCOL.init(Protocol(HidProtocolMode::Report))),
            poll_ms: 10,
            max_packet_size: 8,
            hid_subclass: HidSubclass::Boot,
            hid_boot_protocol: HidBootProtocol::Keyboard,
        },
    );
    let serial = CdcAcmClass::new(&mut builder, CDC_STATE.init(cdc_acm::State::new()), 64);
    let device = builder.build();
    ON_OTG.store(true, Ordering::Relaxed);
    let (tx, rx) = serial.split();
    let failed = |_| Error::msg("cannot start the USB tasks");
    spawner.spawn(run(device).map_err(failed)?);
    spawner.spawn(keys(keyboard).map_err(failed)?);
    spawner.spawn(console_out(tx).map_err(failed)?);
    spawner.spawn(console_in(rx).map_err(failed)?);
    Ok(())
}

#[embassy_executor::task]
async fn run(mut device: UsbDevice<'static, Driver<'static>>) {
    device.run().await
}

#[embassy_executor::task]
async fn keys(mut keyboard: HidWriter<'static, Driver<'static>, 8>) {
    loop {
        let t = TYPE.receive().await;
        keyboard.ready().await;
        let mut typed = true;
        for r in &t.reports {
            if keyboard.write(r).await.is_err() {
                typed = false;
                break;
            }
            Timer::after_millis(t.gap_ms).await;
        }
        if typed {
            println!("cbb-esp32: typed");
        } else {
            // Let go of any key the host saw pressed.
            let _ = keyboard.write(&cbb_core::keyboard::RELEASE).await;
            println!("cbb-esp32: the host stopped taking keys; nothing more was typed");
        }
    }
}

#[embassy_executor::task]
async fn console_out(mut tx: cdc_acm::Sender<'static, Driver<'static>>) {
    // A packet shorter than the endpoint's 64 bytes ends a transfer, so no
    // empty packet is ever needed.
    let mut buf = [0u8; 63];
    loop {
        tx.wait_connection().await;
        loop {
            let n = OUT.read(&mut buf).await;
            if tx.write_packet(&buf[..n]).await.is_err() {
                break;
            }
        }
    }
}

#[embassy_executor::task]
async fn console_in(mut rx: cdc_acm::Receiver<'static, Driver<'static>>) {
    let mut buf = [0u8; 64];
    loop {
        rx.wait_connection().await;
        while let Ok(n) = rx.read_packet(&mut buf).await {
            IN.write_all(&buf[..n]).await;
        }
    }
}

/// Restarts into the ROM's download mode, for espflash, with the USB PHY
/// given back to the USB serial the ROM talks on.
pub fn restart_to_download() -> ! {
    let rtc = LPWR::regs();
    rtc.usb_conf().modify(|_, w| {
        w.sw_hw_usb_phy_sel().clear_bit();
        w.sw_usb_phy_sel().clear_bit()
    });
    rtc.option1().modify(|_, w| w.force_download_boot().set_bit());
    esp_hal::system::software_reset()
}
