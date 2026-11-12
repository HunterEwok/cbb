// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"os"
	"strings"
	"testing"
)

// TestOpen: Open takes the session's display, says which access it chose,
// and says why when there is none.
func TestOpen(t *testing.T) {
	display := os.Getenv("DISPLAY")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	if _, _, err := Open(t.Logf); err == nil || !strings.Contains(err.Error(), "no graphical session") {
		t.Errorf("no display: %v", err)
	}
	t.Setenv("DISPLAY", ":99.42")
	t.Setenv("WAYLAND_DISPLAY", "wayland-none")
	if _, _, err := Open(t.Logf); err == nil {
		t.Error("opened displays that are not there")
	}
	if os.Getenv("CBB_TEST_X11") == "" || display == "" {
		t.Skip("set CBB_TEST_X11 with an X server in DISPLAY")
	}
	t.Setenv("DISPLAY", display)
	// A connection held open keeps Xvfb from resetting, which it does when
	// its last client goes, while the next one connects.
	hold, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	for wayland, want := range map[string]string{"": "X11", "wayland-none": "X11 through XWayland"} {
		t.Setenv("WAYLAND_DISPLAY", wayland)
		b, how, err := Open(t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		b.Close()
		if how != want {
			t.Errorf("with WAYLAND_DISPLAY=%q: %s, want %s", wayland, how, want)
		}
	}
}
