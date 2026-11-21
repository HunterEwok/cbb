// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestFFIPhoneWatch: the root phone adds its watch to a group of 0.6 with
// the key the watch made as its admin key and a member key nobody keeps
// (add_watch; docs/protocol.md, section 10, "Watches"; D-124): the watch
// is listed as a watch, may do nothing to a device, and an action from
// the wrist is refused, saying that it comes with 0.7, where signing on
// the watch moves.
func TestFFIPhoneWatch(t *testing.T) {
	var h hub
	next, in, _, _, phoneID, laptopID := rootPhoneWithLaptop(t, &h)
	fmt.Fprintln(in, "WATCH ADD Wrist")
	var added struct {
		OK struct {
			Device string `json:"device"`
			Name   string `json:"name"`
		} `json:"ok"`
	}
	if got := next("WATCH ADDED "); json.Unmarshal([]byte(got), &added) != nil || added.OK.Device == "" || added.OK.Name != "Wrist" {
		t.Fatalf("adding the watch: %s", got)
	}
	fmt.Fprintln(in, "DEVICES")
	var devices []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if got := next("DEVICES "); json.Unmarshal([]byte(got), &devices) != nil {
		t.Fatalf("the devices: %s", got)
	}
	listed := false
	for _, d := range devices {
		listed = listed || (d.ID == added.OK.Device && d.Name == "Wrist" && d.Role == "watch")
	}
	if !listed {
		t.Fatalf("the watch is not listed as a watch: %+v", devices)
	}
	fmt.Fprintln(in, "WATCH ADD Wrist")
	if got := next("WATCH ADDED "); !strings.Contains(got, "error") {
		t.Fatalf("the same watch was added twice: %s", got)
	}
	manage := func(req string) string {
		fmt.Fprintln(in, "MANAGE "+req)
		return next("MANAGED ")
	}
	for _, id := range []string{phoneID, laptopID} {
		if got := manage(`{"action":"watch_actions","device":"` + id + `"}`); got != `{"ok":{"actions":[]}}` {
			t.Fatalf("the watch's actions on %s: %s", id, got)
		}
	}
	fmt.Fprintln(in, `WATCH {"action":"paste_off","device":"`+laptopID+`"}`)
	seen, got := next("WATCH SAW "), next("WATCHED ")
	if seen != "" || !strings.Contains(got, "error") || !strings.Contains(got, "0.7") {
		t.Fatalf("an action from the wrist: shown %q, answered %s", seen, got)
	}
}
