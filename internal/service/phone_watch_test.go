// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestFFIPhoneWatch: the root phone makes its watch an admin with the key
// the watch made (add_watch), and the watch, shown each command or record
// whole before it signs it, turns remote paste off on the laptop and
// removes it from the wrist (cbb_member_manage_watch; docs/protocol.md,
// section 10, "Watches"). It may do nothing to the root's phone, and what
// it refuses to sign is not done.
func TestFFIPhoneWatch(t *testing.T) {
	var h hub
	next, in, _, _, phoneID, laptopID := rootPhoneWithLaptop(t, &h)
	fmt.Fprintln(in, "WATCH ADD Wrist")
	var added struct {
		OK struct {
			Device  string `json:"device"`
			AdminCA string `json:"admin_ca"`
		} `json:"ok"`
	}
	if got := next("WATCH ADDED "); json.Unmarshal([]byte(got), &added) != nil || added.OK.Device == "" || added.OK.AdminCA == "" {
		t.Fatalf("making the watch an admin: %s", got)
	}
	manage := func(req string) string {
		fmt.Fprintln(in, "MANAGE "+req)
		return next("MANAGED ")
	}
	if got := manage(`{"action":"watch_actions","device":"` + phoneID + `"}`); got != `{"ok":{"actions":[]}}` {
		t.Fatalf("the watch's actions on the root's phone: %s", got)
	}
	if got := manage(`{"action":"watch_actions","device":"` + laptopID + `"}`); got != `{"ok":{"actions":["remove","paste-off","actions-off","away-off","action"]}}` {
		t.Fatalf("the watch's actions on the laptop: %s", got)
	}
	watch := func(req string) (seen, got string) {
		t.Helper()
		fmt.Fprintln(in, "WATCH "+req)
		seen = next("WATCH SAW ")
		return seen, next("WATCHED ")
	}
	if _, got := watch(`{"action":"remove","device":"` + phoneID + `"}`); !strings.Contains(got, "error") {
		t.Fatalf("the watch removed the root's phone: %s", got)
	}
	if _, got := watch(`{"action":"freeze","device":"` + laptopID + `"}`); !strings.Contains(got, "error") {
		t.Fatalf("the watch froze a computer that is no admin: %s", got)
	}
	if seen, got := watch(`{"action":"paste_off","device":"` + laptopID + `","refuse":true}`); seen != "paste-off" || !strings.Contains(got, "did not sign") {
		t.Fatalf("a command the watch refused: %s %s", seen, got)
	}
	if seen, got := watch(`{"action":"paste_off","device":"` + laptopID + `"}`); seen != "paste-off" || !strings.Contains(got, `"status":"done"`) {
		t.Fatalf("turning remote paste off from the wrist: %s %s", seen, got)
	}
	if seen, got := watch(`{"action":"remove","device":"` + laptopID + `"}`); seen != "revoke" || got != `{"ok":{}}` {
		t.Fatalf("removing the laptop from the wrist: %s %s", seen, got)
	}
	waitFor(t, "the laptop is out of the group", func() bool {
		fmt.Fprintln(in, "DEVICES")
		return !strings.Contains(next("DEVICES "), laptopID)
	})
}
