// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The settings in flash: the partition "cbb" of partitions.csv holds two
//! slots, and cbb_core::store decides which one is newest and where the
//! next save goes, so a power cut while saving keeps the last good copy.
//!
//! The flash is not encrypted: whoever holds the board can read what it
//! saves, as with the Wi-Fi password in any other device on the network.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use cbb_core::error::{Context, Error, Result};
use cbb_core::identity::Identity;
use cbb_core::keyboard::Layout;
use cbb_core::store::{self, Fields};
use esp_bootloader_esp_idf::partitions::{self, PartitionEntry, RawPartitionType};
use esp_hal::Blocking;
use esp_hal::flash::Flash;

/// The partition's label in partitions.csv.
const LABEL: &str = "cbb";
/// The size of each slot: half the partition.
const SLOT: u32 = 32 * 1024;
const SECTOR: u32 = 4096;

/// The tags of the saved fields. Never reuse a tag for something else.
pub mod tag {
    pub const WIFI_SSID: u8 = 1;
    pub const WIFI_PASSWORD: u8 = 2;
    /// Errors show their details (1) or not (0); unset follows the build.
    pub const DEBUG: u8 = 3;
    /// The member's identity in the group (cbb_core::identity's file form).
    pub const IDENTITY: u8 = 4;
    /// The USB port is the keyboard and the console's serial port (1), or
    /// the console on the USB serial (0 or unset).
    pub const USB_KEYBOARD: u8 = 5;
    /// The layout active on the host the keyboard types on, by its name
    /// (cbb_core::keyboard::Layout); unset is us.
    pub const LAYOUT: u8 = 6;
    /// The characters the keyboard types a second; unset is RATE.
    pub const RATE: u8 = 7;
    /// The board is a Bluetooth LE keyboard (1), or not (0 or unset).
    pub const BLE_KEYBOARD: u8 = 8;
    /// The hosts the Bluetooth keyboard is paired with (Bond::encode_all).
    pub const BONDS: u8 = 9;
}

/// The most hosts the Bluetooth keyboard stays paired with; a new one
/// pushes out the oldest.
#[cfg_attr(feature = "qemu", allow(dead_code))]
pub const MAX_BONDS: usize = 4;

/// A host the Bluetooth keyboard is paired with: its identity address
/// (the address type and six bytes, least significant first), its identity
/// resolving key if it gave one, and the long-term key of the link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bond {
    pub kind: u8,
    pub addr: [u8; 6],
    pub irk: Option<[u8; 16]>,
    pub ltk: [u8; 16],
    /// Whether the pairing was authenticated (MITM protected).
    pub authenticated: bool,
}

impl Bond {
    const LEN: usize = 1 + 6 + 1 + 16 + 16 + 1;

    /// The bonds one after another, the oldest first.
    pub fn encode_all(bonds: &[Bond]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bonds.len() * Self::LEN);
        for b in bonds {
            out.push(b.kind);
            out.extend_from_slice(&b.addr);
            out.push(b.irk.is_some() as u8);
            out.extend_from_slice(&b.irk.unwrap_or_default());
            out.extend_from_slice(&b.ltk);
            out.push(b.authenticated as u8);
        }
        out
    }

    /// The saved bonds; damaged ones are left out.
    pub fn decode_all(data: &[u8]) -> Vec<Bond> {
        data.as_chunks::<{ Self::LEN }>()
            .0
            .iter()
            .filter_map(|c| {
                let irk = match c[7] {
                    0 => None,
                    1 => Some(c[8..24].try_into().ok()?),
                    _ => return None,
                };
                Some(Bond {
                    kind: c[0],
                    addr: c[1..7].try_into().ok()?,
                    irk,
                    ltk: c[24..40].try_into().ok()?,
                    authenticated: c[40] == 1,
                })
            })
            .collect()
    }
}

/// The keyboard's characters a second unless the user sets another: some
/// TVs drop keys that come faster.
pub const RATE: u8 = 20;
/// The rates the console takes.
pub const RATES: core::ops::RangeInclusive<u8> = 5..=60;

/// A Wi-Fi network to join.
#[derive(Clone)]
pub struct Wifi {
    pub ssid: String,
    /// Empty for an open network.
    pub password: String,
}

pub struct Store {
    flash: Flash<'static, Blocking>,
    part: PartitionEntry,
    fields: Fields,
    newest: Option<(usize, u32)>,
}

impl Store {
    /// Finds the partition and loads the newest intact copy of the fields.
    pub fn open(mut flash: Flash<'static, Blocking>) -> Result<Store> {
        let mut table = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
        let pt = partitions::read_partition_table(&mut flash, &mut table).context("cannot read the partition table")?;
        let part = pt
            .iter()
            .find(|p| p.label_as_str() == LABEL && p.raw_type() == RawPartitionType::Data as u8)
            .ok_or_else(|| Error::msg("the flash has no partition \"cbb\": flash the firmware with partitions.csv"))?;
        if part.len() < 2 * SLOT {
            return Err(Error::msg("the partition \"cbb\" is too small: flash the firmware with partitions.csv"));
        }
        let mut s = Store { flash, part, fields: Fields::default(), newest: None };
        let a = s.read_slot(0)?;
        let b = s.read_slot(1)?;
        if let Some(n) = store::newest(&a, &b) {
            s.newest = Some((n.slot, n.seq));
            s.fields = Fields::decode(n.payload).ok_or_else(|| Error::msg("the saved settings are damaged"))?;
        }
        Ok(s)
    }

    pub fn fields(&self) -> &Fields {
        &self.fields
    }

    pub fn wifi(&self) -> Option<Wifi> {
        let ssid = String::from_utf8(self.fields.get(tag::WIFI_SSID)?.to_vec()).ok()?;
        let password = String::from_utf8(self.fields.get(tag::WIFI_PASSWORD).unwrap_or_default().to_vec()).ok()?;
        Some(Wifi { ssid, password })
    }

    /// Whether the USB port is the keyboard.
    pub fn usb_keyboard(&self) -> bool {
        self.fields.get(tag::USB_KEYBOARD) == Some(&[1])
    }

    /// The layout active on the host the keyboard types on.
    pub fn layout(&self) -> Layout {
        self.fields
            .get(tag::LAYOUT)
            .and_then(|n| core::str::from_utf8(n).ok())
            .and_then(Layout::from_name)
            .unwrap_or(Layout::Us)
    }

    /// The keyboard's characters a second.
    pub fn rate(&self) -> u8 {
        match self.fields.get(tag::RATE) {
            Some(&[r]) if RATES.contains(&r) => r,
            _ => RATE,
        }
    }

    /// Whether the board is a Bluetooth LE keyboard.
    #[cfg_attr(feature = "qemu", allow(dead_code))]
    pub fn ble_keyboard(&self) -> bool {
        self.fields.get(tag::BLE_KEYBOARD) == Some(&[1])
    }

    /// The hosts the Bluetooth keyboard is paired with, the oldest first.
    pub fn bonds(&self) -> Vec<Bond> {
        self.fields.get(tag::BONDS).map(Bond::decode_all).unwrap_or_default()
    }

    /// The identity in the group, if the board joined one.
    pub fn identity(&self) -> Option<Result<Identity>> {
        self.fields.get(tag::IDENTITY).map(Identity::from_file)
    }

    /// Saves fields into the slot after the newest, then keeps them.
    pub fn save(&mut self, fields: Fields) -> Result<()> {
        let (slot, seq) = store::next(self.newest);
        let mut frame = store::frame(seq, &fields.encode());
        if frame.len() > SLOT as usize {
            return Err(Error::msg("the settings do not fit in flash"));
        }
        // Writes go in whole words.
        frame.resize(frame.len().next_multiple_of(4), 0xff);
        let start = slot as u32 * SLOT;
        let mut region = self.part.as_flash_region(&mut self.flash).context("cannot open the flash partition")?;
        region.erase(start, start + (frame.len() as u32).next_multiple_of(SECTOR)).context("cannot erase the flash")?;
        region.write(start, &frame).context("cannot write the flash")?;
        self.newest = Some((slot, seq));
        self.fields = fields;
        Ok(())
    }

    /// The bytes of a slot as far as its frame reaches: the header, and the
    /// rest only when the header names a length that fits.
    fn read_slot(&mut self, slot: usize) -> Result<Vec<u8>> {
        let start = slot as u32 * SLOT;
        let mut region = self.part.as_flash_region(&mut self.flash).context("cannot open the flash partition")?;
        let mut head = [0u8; store::HEADER];
        region.read(start, &mut head).context("cannot read the flash")?;
        let len = match store::frame_len_in(&head) {
            Some(len) if len <= SLOT as usize => len,
            _ => return Ok(head.to_vec()),
        };
        let mut buf = vec![0u8; len];
        region.read(start, &mut buf).context("cannot read the flash")?;
        Ok(buf)
    }
}
