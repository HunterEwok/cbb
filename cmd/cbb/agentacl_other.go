// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

// letServiceQuery is needed on Windows only, where the service runs as an
// account of its own.
func letServiceQuery() error { return nil }
