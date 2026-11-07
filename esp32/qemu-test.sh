#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Tests the firmware in Espressif's QEMU (the ESP32-S3 machine): builds the
# QEMU test build, writes a flash image with espflash and the partition
# table, then qemu-test.py boots it three times and types on its console.
#   QEMU=path/to/qemu-system-xtensa ESPFLASH=path/to/espflash ./qemu-test.sh
set -eu
cd "$(dirname "$0")"
: "${QEMU:=qemu-system-xtensa}" "${ESPFLASH:=espflash}"

cargo +esp build --locked --release --no-default-features --features qemu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$ESPFLASH" save-image --chip esp32s3 --merge --partition-table partitions.csv \
	target/xtensa-esp32s3-none-elf/release/cbb-esp32 "$work/flash.bin"
python3 -I qemu-test.py "$QEMU" "$work/flash.bin" "$work" || {
	cat "$work"/qemu*.log >&2
	exit 1
}
