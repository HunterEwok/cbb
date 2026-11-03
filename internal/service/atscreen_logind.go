// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package service

import (
	"strconv"
	"strings"

	"github.com/HunterEwok/cbb/internal/lockcheck"
)

// atScreen asks logind: the desktop and the actions go to the user of an
// active graphical session, tmux to a user with a session, as one over
// SSH. Without logind nothing tells who is at the screen.
func atScreen(p peer, target string) verdict {
	ids, err := lockcheck.Sessions()
	if err != nil {
		return unchecked
	}
	uid := strconv.FormatUint(uint64(p.uid), 10)
	for _, id := range ids {
		if atScreenIn(lockcheck.Show(id, "User", "State", "Class", "Type", "Remote", "Seat"), uid, target) {
			return allowed
		}
	}
	return refused
}

// atScreenIn reports whether a session with the logind properties m puts
// the user uid at the screen for target: a session of the user's own (not
// its service manager or a greeter); for tmux any that is active or online,
// as over SSH; for the desktop and the actions an active graphical one,
// X11 or Wayland, on a seat or not remote, so that a user signed in over
// SSH alone takes none, even where SSH lets the session name its type.
func atScreenIn(m map[string]string, uid, target string) bool {
	if m["User"] != uid || !strings.HasPrefix(m["Class"], "user") {
		return false
	}
	if target == targetTmux {
		return m["State"] == "active" || m["State"] == "online"
	}
	return m["State"] == "active" && (m["Type"] == "x11" || m["Type"] == "wayland") && (m["Seat"] != "" || m["Remote"] == "no")
}
