// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package helper

import (
	"os"

	"github.com/godbus/dbus/v5"

	"github.com/HunterEwok/cbb/internal/peripheral"
)

// testBus is the bus of a test's BlueZ (internal/blekeyboard/bluetest)
// that CBB_TEST_BLUEZ names, for the Rust service's tests; nil, the system
// bus, otherwise.
func testBus() peripheral.BusDialer {
	addr := os.Getenv("CBB_TEST_BLUEZ")
	if addr == "" {
		return nil
	}
	return func() (*dbus.Conn, error) { return dbus.Connect(addr) }
}
