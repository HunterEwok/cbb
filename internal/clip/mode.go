// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import "fmt"

// Mode says whether a member syncs its clipboard with the group
// (docs/design.md, "Sync on or off"). It changes nothing else: the member
// stays connected, keeps the group's current event and forwards events
// either way, and deliberate actions (Send) work either way.
type Mode uint8

const (
	Shared Mode = iota // sync on: its copies go to the group, and the group's copies reach its clipboard
	Own                // sync off: its clipboard is its own; the group's text is at hand on request (Current)
)

// Sends reports whether the copies a clipboard watcher reports go to the group.
func (m Mode) Sends() bool { return m == Shared }

// Receives reports whether the group's copies are written to the clipboard.
func (m Mode) Receives() bool { return m == Shared }

// String returns the mode's name, as hellos and the mode command carry it.
func (m Mode) String() string {
	switch m {
	case Shared:
		return "shared"
	case Own:
		return "own"
	}
	return fmt.Sprintf("mode(%d)", m)
}

// ParseMode reads a mode's name.
func ParseMode(s string) (Mode, error) {
	for m := Shared; m <= Own; m++ {
		if m.String() == s {
			return m, nil
		}
	}
	return Shared, fmt.Errorf("the sync mode is shared (sync on) or own (sync off), not %q", s)
}
