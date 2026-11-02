// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"sync"

	"github.com/godbus/dbus/v5"
)

// prefersLight asks the desktop portal once whether the user chose a light
// look (org.freedesktop.appearance color-scheme 2). Most panels are dark,
// GNOME's always, so no answer or no preference means dark.
var prefersLight = sync.OnceValue(func() bool {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return false
	}
	defer conn.Close()
	var v dbus.Variant
	err = conn.Object("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop").
		Call("org.freedesktop.portal.Settings.ReadOne", 0, "org.freedesktop.appearance", "color-scheme").Store(&v)
	if err != nil {
		return false
	}
	scheme, _ := v.Value().(uint32)
	return scheme == 2
})
