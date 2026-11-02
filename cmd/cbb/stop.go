// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// stopLines say what the group's records stop and why, and what ends it
// (docs/protocol.md, section 10, "Stopping the exchange"): the conflicts,
// the claims to take the group over, and the records of a later version.
func stopLines(st *control.Status) []string {
	var out []string
	switch st.Stop {
	case "full":
		out = append(out, "The group is stopped: its members exchange records only, no clipboard, until the group's root decides.")
	case "secrets":
		out = append(out, "The group sends no secrets until its root decides.")
	}
	for _, c := range st.Conflicts {
		who := names(c.Devices)
		switch c.Kind {
		case "admins":
			out = append(out, fmt.Sprintf("Admins removed or froze each other without seeing it (%s): the root decides by removing one of them (cbb remove NAME on a root computer, or on the root phone).", who))
		case "claims":
			out = append(out, fmt.Sprintf("Two claims to take the group over (%s): the root cancels one or both by removing its admin.", who))
		case "two_histories":
			out = append(out, fmt.Sprintf("%s signed two histories with one key, as a stolen key or a device brought back from a backup would: the group's root voids both (cbb resolve on a root computer, or on the root phone), and the device signs its records again.", who))
		default:
			out = append(out, fmt.Sprintf("A conflict of kind %s (%s): the root decides.", c.Kind, who))
		}
	}
	for _, c := range st.Claims {
		switch c.State {
		case "pending":
			left := "once this device knows how long it has held it"
			if c.LeftMS > 0 {
				left = "in " + roughly(time.Duration(c.LeftMS)*time.Millisecond)
			}
			out = append(out, fmt.Sprintf("%s claims the group, to take it over from its root: it takes effect %s, unless the root cancels it by removing %s.", c.By, left, c.By))
		case "disputed":
			out = append(out, fmt.Sprintf("%s claims the group, and another admin removed it: the group is stopped until the root decides.", c.By))
		case "competing":
			out = append(out, fmt.Sprintf("%s claims the group while another admin claims it too: the group is stopped until the root decides.", c.By))
		}
	}
	if st.Newer > 0 {
		out = append(out, fmt.Sprintf("The group holds %d records of a later version of Clipboard Bridge: update it to read them.", st.Newer))
	}
	return out
}

// names joins device names for a sentence.
func names(ds []string) string {
	if len(ds) == 0 {
		return "devices unknown here"
	}
	return strings.Join(ds, ", ")
}

// roughly writes a duration in days, hours or minutes.
func roughly(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	case d >= 2*time.Minute:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	return "a minute"
}
