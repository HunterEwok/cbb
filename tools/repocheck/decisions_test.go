// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
)

func TestCheckDecisions(t *testing.T) {
	good := "# Decisions\n\n## Decisions in force\n\n| ID | Status | Decision |\n|---|---|---|\n" +
		"| D-1 | accepted | a |\n| D-3 | partly replaced by D-4 | c |\n| D-4 | accepted | d |\n\n" +
		"## Replaced decisions\n\n| ID | Status | Decision |\n|---|---|---|\n| D-2 | replaced by D-4 | b |\n"
	if got := checkDecisions(map[string][]byte{"docs/decisions.md": []byte(good)}); len(got) != 0 {
		t.Fatalf("checkDecisions(good) = %q, want nothing", got)
	}
	bad := "## Decisions in force\n\n| D-1 | accepted | a |\n| D-2 | replaced by D-4 | b |\n| D-1 | accepted | again |\n" +
		"| D-5 | partly replaced by D-9 | e |\n| D-6 | gone | f |\n\n## Replaced decisions\n\n| D-7 | accepted | g |\n"
	got := checkDecisions(map[string][]byte{"docs/decisions.md": []byte(bad)})
	want := []string{
		":4: D-2 is replaced by D-4; move",
		":5: D-1 is used already on line 3",
		":7: D-6 has the status",
		":11: D-7 is accepted; it belongs",
		":4: D-2 names D-4, which",
		":6: D-5 names D-9, which",
	}
	if len(got) != len(want) {
		t.Fatalf("checkDecisions(bad) = %q, want %d problems", got, len(want))
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) {
			t.Errorf("problem %d = %q, want it to contain %q", i, got[i], w)
		}
	}
}
