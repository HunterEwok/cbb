// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// The installer starts the tray app with each sign-in from the value
// "CBB tray" of HKLM\...\CurrentVersion\Run. A user turns that off and on
// as the Task Manager's Startup apps do: with the same value under their
// own StartupApproved\Run, a binary whose first byte is 2 for on and 3 for
// off.

const (
	trayRunValue    = "cbb tray"
	startupApproved = `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
)

func atLogin() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, startupApproved, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer k.Close()
	v, _, err := k.GetBinaryValue(trayRunValue)
	if err != nil || len(v) == 0 {
		return true
	}
	return v[0]&1 == 0
}

func setAtLogin(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, startupApproved, registry.SET_VALUE)
	if err != nil {
		return errors.Join(errors.New("cannot open StartupApproved"), err)
	}
	defer k.Close()
	v := make([]byte, 12)
	v[0] = 2
	if !on {
		v[0] = 3
	}
	return k.SetBinaryValue(trayRunValue, v)
}
