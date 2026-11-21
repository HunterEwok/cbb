// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"slices"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestJoinByShownCode: on the records of 0.6 the new device does not show
// a code and wait; the group's admin opens a home window and shows its six
// digits, and a new computer that finds the window by mDNS types them, as
// a phone scans the window's QR code. A code typed on the admin with no
// window says how pairing goes now, a wrong code admits nothing, and the
// right one admits the device.
func TestJoinByShownCode(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	if _, err := a.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpPair, Code: "123456"}, ""); err == nil || !strings.Contains(err.Error(), "no device waits") || !strings.Contains(err.Error(), "cbb pair") {
		t.Errorf("a code with no device that waits: %v", err)
	}

	c, code := openWindow(t, a)
	defer c.Close()
	id := a.status(t).Device
	waitFor(t, "alpha announces its window", func() bool { return slices.Contains(h.txtOf(id), "p=1") })
	wrong := "135791"
	if code == wrong {
		wrong = "246810"
	}
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: wrong}, ""); err == nil {
		t.Error("a wrong code admitted the device")
	}
	if st := b.status(t); st.Group != "" {
		t.Fatal("beta is in a group after a wrong code")
	}
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: code[:3] + " " + code[3:]}, ""); err != nil {
		t.Fatalf("joining by the shown code: %v", err)
	}
	// The window tells of the wrong try, then of the device it admitted.
	m, err := c.Receive()
	if err != nil || !m.Refused {
		t.Fatalf("the window on alpha told of the wrong try with %+v, %v", m, err)
	}
	if m, err = c.Receive(); err != nil || m.Name != "beta" {
		t.Fatalf("the window on alpha ended with %+v, %v", m, err)
	}
	waitFor(t, "beta is in alpha's group", func() bool { return b.status(t).Group == a.status(t).Group })
}
