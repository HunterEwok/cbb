// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestCopyLifetimes: the root and the admins set how long a copy and a
// secret live in the group, every member takes them from the records, and
// a member that is no admin may not set them.
func TestCopyLifetimes(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c := startService(t, &h, "gamma")
	pairWith(t, a, b) // alpha is the root
	pairWith(t, a, c)
	if s := b.status(t); s.TTLMS != 300_000 || s.SecretTTLMS != 60_000 {
		t.Fatalf("the lifetimes without a record: %d and %d ms", s.TTLMS, s.SecretTTLMS)
	}
	if _, err := a.do(t, control.Header{Op: control.OpTTL, Value: "30s"}, ""); err == nil {
		t.Error("a copy's lifetime below a minute was signed")
	}
	if _, err := a.do(t, control.Header{Op: control.OpTTL, Value: "- 2m"}, ""); err == nil {
		t.Error("a secret's lifetime past a minute was signed")
	}
	if _, err := b.do(t, control.Header{Op: control.OpTTL, Value: "2m"}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root or an admin") {
		t.Errorf("a member that is no admin set the lifetime: %v", err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpTTL, Value: "2m 20s"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta takes the root's lifetimes", func() bool {
		s := b.status(t)
		return s.TTLMS == 120_000 && s.SecretTTLMS == 20_000
	})

	// An admin sets it too.
	makeAdmin(t, a, c)
	if _, err := c.do(t, control.Header{Op: control.OpTTL, Value: "30m"}, ""); err != nil {
		t.Fatal(err)
	}
	// The root's record beats an admin's, so the root's two minutes stay,
	// on the admin itself too.
	if ms := c.status(t).TTLMS; ms != 120_000 {
		t.Errorf("an admin's record beat the root's: %d ms", ms)
	}
}

// TestRemovedDevicesCopyIsDropped: when a device is removed, the group's
// last copy, made on it, no longer counts on the others.
func TestRemovedDevicesCopyIsDropped(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c := startService(t, &h, "gamma")
	pairWith(t, a, b)
	pairWith(t, a, c)
	waitFor(t, "beta connected to gamma", func() bool { return len(b.status(t).Peers) == 2 })
	if _, err := c.do(t, control.Header{Op: control.OpCopy}, "from gamma"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta has gamma's copy", func() bool { return b.paste(t) == "from gamma" })
	if _, err := a.do(t, control.Header{Op: control.OpRemove, Device: "gamma"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta drops gamma's copy", func() bool { return b.logged("no longer counts and is dropped") })
}
