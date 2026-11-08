// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package agent

// first reports that no other agent runs; launchd starts only one.
func first() bool { return true }
