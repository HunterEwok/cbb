// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The installer starts the tray app with each desktop session from
// /etc/xdg/autostart/cbb-tray.desktop. A user turns that off with an entry
// of the same name in their own autostart folder that says Hidden=true
// (the XDG Autostart specification), and on again by removing it.

const autostartName = "cbb-tray.desktop"

// hiddenEntry is the user's entry that turns the tray app's start off.
const hiddenEntry = "[Desktop Entry]\nType=Application\nName=CBB\nHidden=true\n"

func autostartPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "autostart", autostartName), nil
}

// atLogin tells whether the tray app starts with each sign-in: unless the
// user's own entry hides it.
func atLogin() bool {
	p, err := autostartPath()
	if err != nil {
		return true
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "Hidden=true" {
			return false
		}
	}
	return true
}

func setAtLogin(on bool) error {
	p, err := autostartPath()
	if err != nil {
		return err
	}
	if on {
		// Only the entry this app wrote goes; one the user wrote stays.
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if string(data) != hiddenEntry {
			return errors.New("the autostart folder holds another " + autostartName + "; remove it to start CBB with each sign-in")
		}
		return os.Remove(p)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(hiddenEntry), 0o644)
}
