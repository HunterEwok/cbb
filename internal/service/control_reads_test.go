// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestControlReads asks a member's control socket what the apps and cbb
// update read of it: the version it runs, in a group or not; the tiles to
// draw and a change of their order; the signed release it holds, the way
// to the mirror and a waiting bug report, none here.
func TestControlReads(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	m, err := pi.do(t, control.Header{Op: "version"}, "")
	if err != nil || m.Status == nil || m.Status.Version == "" || m.Status.Role != "member" {
		t.Fatalf("version before a group: %+v, %v", m, err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpView}, ""); err == nil {
		t.Error("the tiles of no group")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	if m, err := pi.do(t, control.Header{Op: "version"}, ""); err != nil || m.Status.Version == "" {
		t.Fatalf("version in a group: %+v, %v", m, err)
	}

	m, err = pi.do(t, control.Header{Op: control.OpView}, "")
	if err != nil || len(m.View) == 0 {
		t.Fatalf("view: %+v, %v", m, err)
	}
	var view map[string]any
	if err := json.Unmarshal(m.View, &view); err != nil {
		t.Fatalf("view %s: %v", m.View, err)
	}
	if !strings.Contains(string(m.View), pi.status(t).Device) {
		t.Errorf("the view does not show this device: %s", m.View)
	}
	newSet := json.RawMessage(`{"op":"new","name":"desk","devices":[]}`)
	if m, err := pi.do(t, control.Header{Op: control.OpArrange, Arrange: newSet}, ""); err != nil || !strings.Contains(string(m.View), "desk") {
		t.Errorf("arrange new: %+v, %v", m, err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpArrange}, ""); err == nil || !strings.Contains(err.Error(), "which change") {
		t.Errorf("arrange without a change: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpArrange, Arrange: json.RawMessage(`{"op":"fly"}`)}, ""); err == nil || !strings.Contains(err.Error(), "does not read") {
		t.Errorf("arrange of an unknown change: %v", err)
	}

	if _, err := pi.do(t, control.Header{Op: control.OpReleaseHeld}, ""); err == nil || !strings.Contains(err.Error(), "no signed release") {
		t.Errorf("release_held without one: %v", err)
	}
	if m, err := pi.do(t, control.Header{Op: control.OpUpdateWay}, ""); err != nil || len(m.Payload) != 0 {
		t.Errorf("update_way without VLESS: %+v, %v", m, err)
	}
	if m, err := pi.do(t, control.Header{Op: control.OpBug}, ""); err != nil || len(m.Payload) != 0 {
		t.Errorf("bug with none waiting: %+v, %v", m, err)
	}
}
