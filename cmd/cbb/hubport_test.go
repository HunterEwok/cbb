// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// The hub's port opens only with consent and closes when the hub moves.
func TestSyncHubPort(t *testing.T) {
	oldFW, oldElevated := hubFW, elevated
	t.Cleanup(func() { hubFW, elevated = oldFW, oldElevated })
	opened := 0
	var calls []string
	hubFW = &hubFirewall{
		name:     "fake",
		active:   func() bool { return true },
		opened:   func() int { return opened },
		open:     func(p int) error { calls = append(calls, "open"); opened = p; return nil },
		close:    func() error { calls = append(calls, "close"); opened = 0; return nil },
		commands: func(p int) []string { return []string{"  open it by hand"} },
	}
	elevated = func() bool { return true }
	hub := &control.Away{Hub: true, Port: 9000, Endpoints: []string{"203.0.113.7:9000"}}
	run := func(a *control.Away, mode, answer string) string {
		var out strings.Builder
		syncHubPort(strings.NewReader(answer), &out, a, mode)
		return out.String()
	}
	if out := run(hub, "ask", ""); opened != 0 || !strings.Contains(out, "taken as No") || !strings.Contains(out, "open it by hand") {
		t.Fatalf("no answer: %d\n%s", opened, out)
	}
	if out := run(hub, "ask", "n\n"); opened != 0 || !strings.Contains(out, "Allow incoming UDP 9000 from any address") {
		t.Fatalf("no: %d\n%s", opened, out)
	}
	if run(hub, "ask", "y\n"); opened != 9000 {
		t.Fatalf("yes: %d", opened)
	}
	calls = nil
	if run(hub, "ask", ""); len(calls) != 0 {
		t.Fatalf("already open, yet %v", calls)
	}
	moved := &control.Away{Hub: true, Port: 9001, Endpoints: []string{"203.0.113.7:9001"}}
	if run(moved, "yes", ""); opened != 9001 || strings.Join(calls, " ") != "close open" {
		t.Fatalf("moved: %d %v", opened, calls)
	}
	// Through a forwarder or off, nothing faces the internet.
	if run(&control.Away{Hub: true, Port: 9001}, "ask", ""); opened != 0 {
		t.Fatalf("forwarder: %d", opened)
	}
	run(hub, "yes", "")
	if run(nil, "ask", ""); opened != 0 {
		t.Fatalf("off: %d", opened)
	}
	// Without root it only says what to run.
	elevated = func() bool { return false }
	if out := run(hub, "yes", ""); opened != 0 || !strings.Contains(out, "open it by hand") {
		t.Fatalf("without root: %d\n%s", opened, out)
	}
}

// cbb status says when members at home could not connect to this device.
func TestWriteUnreached(t *testing.T) {
	var out strings.Builder
	writeUnreached(&out, &control.Status{Port: 9000}, nil)
	if out.Len() != 0 {
		t.Fatalf("nothing unreached, yet: %s", out.String())
	}
	writeUnreached(&out, &control.Status{Port: 9000, Unreached: []string{"id1", "id2"}}, []control.Device{{ID: "id1", Name: "deck"}})
	if s := out.String(); !strings.Contains(s, "deck, id2 could not connect") || !strings.Contains(s, "TCP 9000") {
		t.Fatalf("unreached: %s", s)
	}
}
