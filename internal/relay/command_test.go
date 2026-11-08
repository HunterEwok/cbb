// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import "testing"

func TestPortOf(t *testing.T) {
	for in, want := range map[string]string{"[::]:8765": "8765", "0.0.0.0:443": "443", "8764": "8764"} {
		if got := portOf(in); got != want {
			t.Errorf("portOf(%q) = %q, want %q", in, got, want)
		}
	}
}
