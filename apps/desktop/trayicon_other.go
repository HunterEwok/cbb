// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package main

// prefersLight: on Windows the system switches the tray's two pictures by
// itself.
func prefersLight() bool { return false }
