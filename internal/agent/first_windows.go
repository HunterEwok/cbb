// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package agent

import (
	"errors"

	"golang.org/x/sys/windows"
)

// first reports whether no other agent runs in this session. Its mutex
// stays open until the agent exits, so a second agent sees it and leaves.
func first() bool {
	name, _ := windows.UTF16PtrFromString(`Local\cbb-agent`)
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(h)
		return false
	}
	return true // without a mutex, running twice beats not running
}
