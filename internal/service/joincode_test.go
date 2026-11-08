// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestJoinByShownCode: a new computer shows a code and waits, announced by
// mDNS; a computer of the group types that code and admits it, as a phone
// would scan its QR code. A wrong code admits nothing, and a code with no
// device that waits says so.
func TestJoinByShownCode(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	if _, err := a.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpPair, Code: "123456"}, ""); err == nil || !strings.Contains(err.Error(), "no device that waits") {
		t.Errorf("a code with no device that waits: %v", err)
	}

	jc := b.dial(t)
	defer jc.Close()
	m, err := jc.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Code: "246810", Listen: true, Expires: 300}})
	if err != nil || m.Fingerprint == "" {
		t.Fatalf("listening join on beta: %+v, %v", m, err)
	}
	waitFor(t, "beta announces that it waits", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		for d := range h.members {
			for _, s := range d.peer().TXT {
				if s == "j=1" {
					return true
				}
			}
		}
		return false
	})
	if _, err := a.do(t, control.Header{Op: control.OpPair, Code: "135791"}, ""); err == nil {
		t.Error("a wrong code admitted the device")
	}
	got, err := a.do(t, control.Header{Op: control.OpPair, Code: "246 810"}, "")
	if err != nil || got.Name != "beta" {
		t.Fatalf("admitting by the shown code: %+v, %v", got, err)
	}
	if m, err := jc.Receive(); err != nil || !m.Done {
		t.Fatalf("the join on beta ended with %+v, %v", m, err)
	}
	waitFor(t, "beta is in alpha's group", func() bool { return b.status(t).Group == a.status(t).Group })
}
