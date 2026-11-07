// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Where the console's and the log's lines go: the chip's USB serial
//! (UART0 in the QEMU build) through esp-println, or, while the USB port is
//! a keyboard, the console's serial port beside the keyboard (usb.rs).
//! print! and println! here stand in for esp-println's.

use core::fmt;

/// Writes formatted text where the console is now.
pub fn write_fmt(args: fmt::Arguments) {
    #[cfg(feature = "board")]
    if crate::usb::console_on_otg() {
        crate::usb::console_write(args);
        return;
    }
    esp_println::print!("{args}");
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::out::write_fmt(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::out::write_fmt(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::out::write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}
