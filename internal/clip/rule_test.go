// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestRuleVectors checks the rule of incoming copies on every case of
// testdata/interop/copy-verdicts.json, which the Rust core reads too:
// Go's copy of it always, and the core's through Decide when the build
// links it.
func TestRuleVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/interop/copy-verdicts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name     string    `json:"name"`
			Incoming *Incoming `json:"incoming"`
			Verdict  Verdict   `json:"verdict"`
			UntilMS  *int64    `json:"until_ms"`
			NowMS    int64     `json:"now_ms"`
			Holds    *bool     `json:"holds"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 10 {
		t.Fatalf("%d cases", len(f.Cases))
	}
	for _, c := range f.Cases {
		if c.Incoming != nil {
			if got := decide(*c.Incoming); got != c.Verdict {
				t.Errorf("%s: Go says %s, the case %s", c.Name, got, c.Verdict)
			}
			got, err := Decide(*c.Incoming)
			if err != nil || got != c.Verdict {
				t.Errorf("%s: Decide says %s (%v), the case %s", c.Name, got, err, c.Verdict)
			}
		}
		if c.Holds != nil {
			var until *time.Time
			if c.UntilMS != nil {
				u := time.Time{}
				if *c.UntilMS != 0 {
					u = time.UnixMilli(*c.UntilMS)
				}
				until = &u
			}
			if got := holds(until, time.UnixMilli(c.NowMS)); got != *c.Holds {
				t.Errorf("%s: holds says %v", c.Name, got)
			}
		}
	}
}
