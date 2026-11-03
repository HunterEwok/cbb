// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

func TestHolderLine(t *testing.T) {
	for _, c := range []struct {
		st   control.Status
		want string
	}{
		{control.Status{HoldSetting: "auto"}, "Holder of cbb.local: setting auto, no battery."},
		{control.Status{Group: "g", HoldSetting: "auto", HoldPriority: 1, Holder: true}, "Answers for cbb.local (first; setting auto, no battery)."},
		{control.Status{Group: "g", HoldSetting: "auto", HoldPriority: 2, Battery: true},
			"Answers for cbb.local as a fallback when elected; another member does now (setting auto, a laptop)."},
		{control.Status{Group: "g", HoldSetting: "never"}, "Never holds cbb.local (setting never)."},
		{control.Status{Group: "g", HoldSetting: "first"}, "Never holds cbb.local: it does not hold the group's iPhone key."},
	} {
		if got := holderLine(&c.st); got != c.want {
			t.Errorf("holderLine(%+v) = %q, want %q", c.st, got, c.want)
		}
	}
}
