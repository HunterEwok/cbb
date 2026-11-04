// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The console on the board's USB port (UART0 in the QEMU build): a line of
//! text per command, typed in any serial terminal such as espflash's
//! monitor. It sets the Wi-Fi network up, shows the state and runs the
//! self-test. The board echoes what is typed, and stars for a password.

use alloc::string::String;
use alloc::vec::Vec;

use cbb_core::error::{self, Error, Result};
use cbb_core::keyboard::Layout;
use cbb_core::store::Fields;

use crate::selftest;
use crate::store::{RATES, Store, Wifi, tag};
use crate::{print, println};

/// The longest line the console takes: a Wi-Fi password is at most 64
/// bytes, a text to type may be longer.
const MAX_LINE: usize = 256;

/// The name the board joins a group under when pair names none.
const DEFAULT_NAME: &str = "Nano ESP32";

/// Starts listening for the phone and shows the code to paste in the app.
fn pair(board: &mut dyn Board, name: &str) {
    match board.join(name) {
        Ok(text) => {
            println!("In the CBB app, tap \"Connect a new device\" and paste this:");
            println!();
            println!("{text}");
            println!();
            println!("The board waits up to 5 minutes; type status to see how it went.");
        }
        Err(e) => println!("{}", e.for_user()),
    }
}

/// Whether the console has the type command: it types any text on the
/// keyboard for whatever reaches the console, a program on the computer at
/// the USB port among them, so only a build with the feature console-type
/// has it.
const TYPE_COMMAND: bool = cfg!(feature = "console-type");

/// What the console asks of the rest of the firmware.
pub trait Board {
    /// How the network is doing, in a line.
    fn network(&self) -> String;
    /// Joins this Wi-Fi network instead of the one before, or leaves it.
    fn wifi(&mut self, wifi: Option<Wifi>);
    /// Starts listening for the phone, under this name; returns the QR
    /// code's text.
    fn join(&mut self, name: &str) -> Result<String>;
    /// Types these reports, gap_ms apart, on a connected Bluetooth host or
    /// else the USB keyboard, and returns at once; an error when neither is
    /// there or the keyboard is still typing.
    fn type_reports(&mut self, reports: Vec<[u8; 8]>, gap_ms: u64) -> Result<()>;
    /// How the Bluetooth keyboard is doing, in a line.
    fn bluetooth(&self) -> String;
    /// Makes the Bluetooth keyboard discoverable for two minutes.
    fn ble_pair(&mut self) -> Result<()>;
    /// Restarts the board; with download, into the ROM's download mode,
    /// for espflash.
    fn restart(&mut self, download: bool) -> !;
}

enum Ask {
    Command,
    Ssid,
    Password(String),
}

pub struct Console {
    line: Vec<u8>,
    ask: Ask,
    last: u8,
}

impl Console {
    pub fn new() -> Console {
        Console { line: Vec::new(), ask: Ask::Command, last: 0 }
    }

    pub fn start(&self) {
        println!();
        println!("cbb-esp32 {}: type help for the commands", env!("CARGO_PKG_VERSION"));
        self.prompt();
    }

    fn prompt(&self) {
        match self.ask {
            Ask::Command => print!("cbb> "),
            Ask::Ssid => print!("Wi-Fi network name: "),
            Ask::Password(_) => print!("Password (empty for an open network): "),
        }
    }

    /// Takes one byte from the terminal.
    pub fn feed(&mut self, b: u8, store: &mut Result<Store>, board: &mut dyn Board) {
        let last = core::mem::replace(&mut self.last, b);
        match b {
            b'\n' if last == b'\r' => {}
            b'\r' | b'\n' => {
                println!();
                let line = core::mem::take(&mut self.line);
                match String::from_utf8(line) {
                    Ok(line) => self.line_done(line.trim(), store, board),
                    Err(_) => println!("That line is not valid UTF-8; type it again."),
                }
                self.prompt();
            }
            // Backspace and delete.
            0x08 | 0x7f => {
                if self.line.pop().is_some() {
                    // A whole UTF-8 character goes, not one of its bytes.
                    while self.line.last().is_some_and(|c| c & 0xc0 == 0x80) {
                        self.line.pop();
                    }
                    print!("\x08 \x08");
                }
            }
            // Ctrl-C drops the line and any question.
            0x03 => {
                self.line.clear();
                self.ask = Ask::Command;
                println!("^C");
                self.prompt();
            }
            b if b < 0x20 => {}
            b => {
                if self.line.len() < MAX_LINE {
                    self.line.push(b);
                    if matches!(self.ask, Ask::Password(_)) {
                        if b & 0xc0 != 0x80 {
                            print!("*");
                        }
                    } else {
                        // A character once its last byte is in.
                        let start = self.line.iter().rposition(|c| c & 0xc0 != 0x80).unwrap_or(0);
                        if let Ok(c) = core::str::from_utf8(&self.line[start..]) {
                            print!("{c}");
                        }
                    }
                }
            }
        }
    }

    /// Starts pairing by itself once the board has an address and is in
    /// no group, as if pair had been typed, so that a board without a
    /// keyboard at hand shows its code as soon as its Wi-Fi is up. A board
    /// in a group, or one whose settings cannot be read, stays quiet.
    #[cfg_attr(feature = "qemu", allow(dead_code))]
    pub fn offer_pair(&mut self, store: &Result<Store>, board: &mut dyn Board) {
        match store {
            Ok(s) if s.identity().is_none() => {}
            _ => return,
        }
        println!();
        println!("The board is in no group yet, so it starts pairing (type pair again later if it times out).");
        pair(board, DEFAULT_NAME);
        // What was being typed stays, so show it again after the prompt.
        self.prompt();
        match self.ask {
            Ask::Password(_) => {
                for _ in core::str::from_utf8(&self.line).unwrap_or("").chars() {
                    print!("*");
                }
            }
            _ => print!("{}", core::str::from_utf8(&self.line).unwrap_or("")),
        }
    }

    fn line_done(&mut self, line: &str, store: &mut Result<Store>, board: &mut dyn Board) {
        match core::mem::replace(&mut self.ask, Ask::Command) {
            Ask::Command => self.command(line, store, board),
            Ask::Ssid if line.is_empty() => {
                println!("Nothing changed.");
            }
            Ask::Ssid if line.len() > 32 => {
                println!("A Wi-Fi network name is at most 32 bytes.");
            }
            Ask::Ssid => {
                self.ask = Ask::Password(line.into());
            }
            Ask::Password(_) if line.len() > 64 => {
                println!("A Wi-Fi password is at most 64 bytes.");
            }
            Ask::Password(_) if !line.is_empty() && line.len() < 8 => {
                println!("A Wi-Fi password has at least 8 characters.");
            }
            Ask::Password(ssid) => {
                let wifi = Wifi { ssid, password: line.into() };
                let saved = edit(store, |f| {
                    f.set(tag::WIFI_SSID, wifi.ssid.as_bytes());
                    f.set(tag::WIFI_PASSWORD, wifi.password.as_bytes());
                });
                match saved {
                    Ok(()) => println!("Saved. Joining {}.", wifi.ssid),
                    Err(e) => println!("{}\nJoining {} until the board restarts.", e.for_user(), wifi.ssid),
                }
                board.wifi(Some(wifi));
            }
        }
    }

    fn command(&mut self, line: &str, store: &mut Result<Store>, board: &mut dyn Board) {
        let mut words = line.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (None, ..) => {}
            (Some("help"), None, _) => {
                println!("  status        what the board knows and how its network is doing");
                println!("  wifi          set the Wi-Fi network to join (asks for its name and password)");
                println!("  wifi forget   leave the Wi-Fi network and forget it");
                println!("  pair [NAME]   join a group: shows a code to scan with the phone (name: Nano ESP32);");
                println!("                the board starts it by itself once its Wi-Fi is up while it is in no group");
                println!("  leave         forget the group (remove the board in the app too)");
                println!("  debug on|off  show the details of errors, or not (debug build: on by default)");
                println!("  selftest      run the TLS 1.3 self-test");
                println!("  usb keyboard  make the USB port a keyboard, with the console beside it; restarts");
                println!("  usb console   make the USB port the console again; restarts");
                println!("  layout [us|ru] the layout active on the host the keyboard types on");
                println!(
                    "  rate [N]      how many characters a second the keyboard types ({}-{})",
                    RATES.start(),
                    RATES.end()
                );
                println!("  ble on|off    make the board a Bluetooth LE keyboard, or not; restarts");
                println!("  ble pair      let a TV, tablet or computer find the Bluetooth keyboard for 2 minutes");
                println!("  ble forget    forget every host the Bluetooth keyboard is paired with; restarts");
                if TYPE_COMMAND {
                    println!(
                        "  type TEXT     type TEXT on the Bluetooth host if one is connected, else the USB keyboard"
                    );
                }
                println!("  flash         restart into download mode, for espflash");
            }
            (Some("status"), None, _) => {
                println!("  firmware: cbb-esp32 {}", env!("CARGO_PKG_VERSION"));
                match store {
                    Ok(s) => match s.wifi() {
                        Some(w) => println!("  Wi-Fi network: {}", w.ssid),
                        None => println!("  Wi-Fi network: none set, type wifi"),
                    },
                    Err(e) => println!("  settings: {}", e.for_user()),
                }
                if let Ok(s) = store {
                    match s.identity() {
                        Some(Ok(id)) => println!("  group: {} as {}", id.tag(), id.id),
                        Some(Err(e)) => println!("  group: {}", e.for_user()),
                        None => println!("  group: none, type pair"),
                    }
                }
                println!("  network: {}", board.network());
                if let Ok(s) = store {
                    let usb = if s.usb_keyboard() { "keyboard and console" } else { "console" };
                    println!("  USB port: {usb}; layout {}, {} characters a second", s.layout().name(), s.rate());
                }
                if let Ok(s) = store {
                    let hosts = s.bonds().len();
                    println!("  Bluetooth keyboard: {}; paired with {hosts} host(s)", board.bluetooth());
                }
                println!("  error details: {}", if error::show_details() { "on" } else { "off" });
            }
            (Some("wifi"), None, _) => {
                self.ask = Ask::Ssid;
            }
            (Some("wifi"), Some("forget"), None) => {
                match edit(store, |f| {
                    f.remove(tag::WIFI_SSID);
                    f.remove(tag::WIFI_PASSWORD);
                }) {
                    Ok(()) => println!("Forgot the Wi-Fi network."),
                    Err(e) => println!("{}", e.for_user()),
                }
                board.wifi(None);
            }
            (Some("debug"), Some(mode @ ("on" | "off")), None) => {
                let on = mode == "on";
                error::set_show_details(on);
                if let Err(e) = edit(store, |f| f.set(tag::DEBUG, [on as u8])) {
                    println!("{}", e.for_user());
                }
                println!("Error details are {mode}.");
            }
            (Some("pair"), ..) => {
                if let Ok(s) = store
                    && let Some(Ok(id)) = s.identity()
                {
                    println!("The board is in the group {} already; type leave first to join another.", id.tag());
                    return;
                }
                let name = line["pair".len()..].trim();
                pair(board, if name.is_empty() { DEFAULT_NAME } else { name });
            }
            (Some("leave"), None, _) => match edit(store, |f| f.remove(tag::IDENTITY)) {
                Ok(()) => println!("The board left its group. Remove it in the app too, so the group revokes it."),
                Err(e) => println!("{}", e.for_user()),
            },
            (Some("usb"), None, _) => match store {
                Ok(s) if s.usb_keyboard() => println!("The USB port is a keyboard, with the console beside it."),
                Ok(_) => println!("The USB port is the console. Type usb keyboard to make it a keyboard."),
                Err(e) => println!("{}", e.for_user()),
            },
            (Some("usb"), Some(mode @ ("keyboard" | "console")), None) => {
                let keyboard = mode == "keyboard";
                match edit(store, |f| f.set(tag::USB_KEYBOARD, [keyboard as u8])) {
                    Ok(()) => {
                        if keyboard {
                            println!(
                                "Restarting with the USB port as a keyboard. The console is then a serial port of its own:"
                            );
                            println!(
                                "open it in a terminal (espflash monitor finds it too). To flash, type flash there."
                            );
                        } else {
                            println!("Restarting with the USB port as the console.");
                        }
                        board.restart(false);
                    }
                    Err(e) => println!("{}", e.for_user()),
                }
            }
            (Some("ble"), None, _) => println!("The Bluetooth keyboard is {}.", board.bluetooth()),
            (Some("ble"), Some(mode @ ("on" | "off")), None) => {
                let on = mode == "on";
                match edit(store, |f| f.set(tag::BLE_KEYBOARD, [on as u8])) {
                    Ok(()) => {
                        if on {
                            println!(
                                "Restarting as a Bluetooth keyboard. Then type ble pair, and pair the host from its"
                            );
                            println!("Bluetooth settings within two minutes.");
                        } else {
                            println!(
                                "Restarting without the Bluetooth keyboard. The hosts stay paired; ble forget forgets them."
                            );
                        }
                        board.restart(false);
                    }
                    Err(e) => println!("{}", e.for_user()),
                }
            }
            (Some("ble"), Some("pair"), None) => match board.ble_pair() {
                Ok(()) => {
                    println!("For two minutes a TV, tablet or computer can find \"CBB Nano ESP32\" in its Bluetooth");
                    println!("settings; pair it there. Then set its layout with layout us or ru.");
                }
                Err(e) => println!("{}", e.for_user()),
            },
            (Some("ble"), Some("forget"), None) => match edit(store, |f| f.remove(tag::BONDS)) {
                Ok(()) => {
                    println!("Forgot every paired host; forget the board on them too. Restarting.");
                    board.restart(false);
                }
                Err(e) => println!("{}", e.for_user()),
            },
            (Some("layout"), None, _) => match store {
                Ok(s) => println!("The keyboard types for the layout {}.", s.layout().name()),
                Err(e) => println!("{}", e.for_user()),
            },
            (Some("layout"), Some(name), None) => match Layout::from_name(name) {
                Some(l) => match edit(store, |f| f.set(tag::LAYOUT, l.name().as_bytes())) {
                    Ok(()) => {
                        println!("The keyboard types for the layout {} now; set the same layout on the host.", l.name())
                    }
                    Err(e) => println!("{}", e.for_user()),
                },
                None => println!("The keyboard knows the layouts us and ru."),
            },
            (Some("rate"), None, _) => match store {
                Ok(s) => println!("The keyboard types {} characters a second.", s.rate()),
                Err(e) => println!("{}", e.for_user()),
            },
            (Some("rate"), Some(n), None) => match n.parse::<u8>() {
                Ok(r) if RATES.contains(&r) => match edit(store, |f| f.set(tag::RATE, [r])) {
                    Ok(()) => println!("The keyboard types {r} characters a second now."),
                    Err(e) => println!("{}", e.for_user()),
                },
                _ => println!("A rate is {} to {} characters a second.", RATES.start(), RATES.end()),
            },
            (Some("type"), Some(_), _) if !TYPE_COMMAND => {
                println!(
                    "This firmware's console does not type; a build with the feature console-type has the type command."
                );
            }
            (Some("type"), Some(_), _) => {
                let text = line["type".len()..].trim_start();
                let (layout, rate) = match store {
                    Ok(s) => (s.layout(), s.rate()),
                    Err(_) => (Layout::Us, crate::store::RATE),
                };
                match layout.reports(text) {
                    Some(reports) => {
                        // Two reports a character: the key down, then up.
                        match board.type_reports(reports, 500 / u64::from(rate)) {
                            Ok(()) => println!("Typing {} characters.", text.chars().count()),
                            Err(e) => println!("{}", e.for_user()),
                        }
                    }
                    None => {
                        let missing: String = layout.untypeable(text).into_iter().collect();
                        println!("The layout {} has no keys for: {missing}", layout.name());
                    }
                }
            }
            (Some("flash"), None, _) => {
                println!(
                    "Restarting into download mode for espflash. Flashing, or the reset button, starts the firmware again."
                );
                board.restart(true);
            }
            (Some("selftest"), None, _) => match selftest::run() {
                Ok(()) => println!("cbb-esp32: self-test passed"),
                Err(e) => println!("cbb-esp32: self-test failed: {}", e.for_user()),
            },
            _ => {
                println!("Unknown command; type help.");
            }
        }
    }
}

/// Changes the saved fields and saves them.
fn edit(store: &mut Result<Store>, change: impl FnOnce(&mut Fields)) -> Result<()> {
    let Ok(s) = store.as_mut() else {
        return Err(Error::msg("cannot save the settings: the flash storage did not open (see status)"));
    };
    let mut fields = s.fields().clone();
    change(&mut fields);
    s.save(fields)
}

/// Saves the hosts the Bluetooth keyboard is paired with.
#[cfg_attr(feature = "qemu", allow(dead_code))]
pub fn save_bonds(store: &mut Result<Store>, bonds: &[crate::store::Bond]) -> Result<()> {
    edit(store, |f| f.set(tag::BONDS, crate::store::Bond::encode_all(bonds)))
}

/// Saves the identity the board joined with.
#[cfg_attr(feature = "qemu", allow(dead_code))]
pub fn save_identity(store: &mut Result<Store>, id: &cbb_core::identity::Identity) -> Result<()> {
    let file = id.to_file()?;
    edit(store, |f| f.set(tag::IDENTITY, file))
}
