// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"embed"
	"runtime"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// The tray's single-colour glyph in its three states, drawn by tools/icon:
// white for a dark taskbar or panel, black for a light one.
//
//go:embed trayicon/*.ico trayicon/*.png
var trayIcons embed.FS

// trayState names the glyph for a state: the plain one without a group
// or with a problem, the group's mark in one, filled while another device
// is online, as the Mac's menu bar shows it.
func trayState(s State) string {
	if s.Problem != "" || s.Status == nil || s.Status.Group == "" {
		return "tray"
	}
	for _, d := range s.Devices {
		if d.Online && !d.Self {
			return "tray-online"
		}
	}
	return "tray-group"
}

// trayIcon reads the glyph of a state in a colour, as the system takes it:
// an ICO on Windows, a PNG elsewhere.
func trayIcon(state, colour string) []byte {
	ext := ".png"
	if runtime.GOOS == "windows" {
		ext = ".ico"
	}
	b, err := trayIcons.ReadFile("trayicon/" + state + "-" + colour + ext)
	if err != nil {
		panic(err) // embedded above; tools/icon -check keeps every file there
	}
	return b
}

// setTrayIcon shows the glyph of a state. Windows switches between the
// black (light taskbar) and the white (dark taskbar) one with its theme; a
// Linux panel takes one picture, white unless the desktop prefers light.
func setTrayIcon(t *application.SystemTray, state string) {
	if runtime.GOOS == "windows" {
		t.SetIcon(trayIcon(state, "black"))
		t.SetDarkModeIcon(trayIcon(state, "white"))
		return
	}
	colour := "white"
	if prefersLight() {
		colour = "black"
	}
	t.SetIcon(trayIcon(state, colour))
}
