// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// TestStopLines checks what cbb status says when the records stop the
// exchange: the stop, each conflict and claim with what ends it, and the
// records of a later version; nothing when nothing stops.
func TestStopLines(t *testing.T) {
	if l := stopLines(&control.Status{}); len(l) != 0 {
		t.Errorf("nothing stops, got %q", l)
	}
	st := &control.Status{Stop: "full", Newer: 2,
		Conflicts: []control.Conflict{{Kind: "admins", Devices: []string{"Laptop", "Desk"}}, {Kind: "two_histories", Devices: []string{"Pi"}}},
		Claims: []control.Claim{
			{By: "Laptop", State: "pending", LeftMS: (50 * time.Hour).Milliseconds()},
			{By: "Desk", State: "pending"},
			{By: "Old", State: "disputed"},
		}}
	got := strings.Join(stopLines(st), "\n")
	for _, want := range []string{
		"exchange records only", "Laptop, Desk", "cbb remove NAME", "Pi signed two histories", "cbb resolve",
		"takes effect in 2 days", "once this device knows how long", "Old claims the group, and another admin removed it",
		"2 records of a later version",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if got := strings.Join(stopLines(&control.Status{Stop: "secrets"}), "\n"); !strings.Contains(got, "no secrets") {
		t.Errorf("stop secrets: %q", got)
	}
	for d, want := range map[time.Duration]string{3 * time.Hour: "3 hours", 30 * time.Minute: "30 minutes", time.Second: "a minute"} {
		if got := roughly(d); got != want {
			t.Errorf("roughly(%v) = %q, want %q", d, got, want)
		}
	}
}
