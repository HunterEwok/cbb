// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package helper

import "github.com/HunterEwok/cbb/internal/peripheral"

// testBus is nil: only Linux has the Bluetooth keyboard.
func testBus() peripheral.BusDialer { return nil }
