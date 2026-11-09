// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
)

// TestContainerHoldsNoKeys checks a member in a container: it makes no
// group, offers no admin key, so the root cannot make it an admin, and so
// cannot be the hub; the user's CBB_KEYS_IN_FILE=yes allows all of it.
func TestContainerHoldsNoKeys(t *testing.T) {
	var h hub
	nas := startEnv(t, &h, "nas", "CBB_CONTAINER=docker")
	if _, err := nas.do(t, control.Header{Op: control.OpNew}, ""); err == nil || !strings.Contains(err.Error(), "container") || !strings.Contains(err.Error(), "CBB_KEYS_IN_FILE=yes") {
		t.Fatalf("cbb new in a container: %v", err)
	}

	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	pairWith(t, pi, nas)
	waitFor(t, "pi and nas connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if id, err := group.Load(nas.dir); err != nil || id.AdminKey != nil {
		t.Fatalf("the container made an admin key: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Name: "nas"}, ""); err == nil || !strings.Contains(err.Error(), "offers no admin key") {
		t.Fatalf("making the container an admin: %v", err)
	}
	if _, err := nas.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := nas.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Addrs: []string{"127.0.0.1:1"}}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root or an admin") {
		t.Fatalf("the container as the hub: %v", err)
	}

	// Allowed, the same container takes an admin key and becomes an admin.
	allowed := startEnv(t, &h, "nas2", "CBB_CONTAINER=docker", "CBB_KEYS_IN_FILE=yes")
	pairWith(t, pi, allowed)
	makeAdmin(t, pi, allowed)
}

// TestRootlessHoldsNoKeys checks a rootless install (D-79): it makes no
// group and offers no admin key, the root records it as rootless from its
// hello and refuses to make it an admin even with -allow-file-key, and it
// cannot be the hub; nothing allows any of it.
func TestRootlessHoldsNoKeys(t *testing.T) {
	var h hub
	box := startEnv(t, &h, "box", "CBB_ROOTLESS=1", "CBB_KEYS_IN_FILE=yes")
	if _, err := box.do(t, control.Header{Op: control.OpNew}, ""); err == nil || !strings.Contains(err.Error(), "without root") {
		t.Fatalf("cbb new rootless: %v", err)
	}

	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	pairWith(t, pi, box)
	waitFor(t, "pi and box connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if id, err := group.Load(box.dir); err != nil || id.AdminKey != nil {
		t.Fatalf("the rootless install made an admin key: %v", err)
	}
	waitFor(t, "box recorded as rootless", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "box" {
				return d.Store == group.StoreRootless
			}
		}
		return false
	})
	if _, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Name: "box", Consent: true}, ""); err == nil || !strings.Contains(err.Error(), "without root") {
		t.Fatalf("making the rootless install an admin: %v", err)
	}
	if _, err := box.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := box.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Addrs: []string{"127.0.0.1:1"}}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root or an admin") {
		t.Fatalf("the rootless install as the hub: %v", err)
	}
}
