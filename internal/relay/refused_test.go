// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
)

// A registration the relay refuses leaves it as it was: whatever the
// reason, it keeps nothing of the refused device's group, its period or
// records, and the devices registered before stay as they were.
func TestRefusedRegistrationLeavesState(t *testing.T) {
	r, link := startWith(t, Config{Open: true, Limits: Limits{Groups: 3, PerAddress: 4}})
	ctx := context.Background()
	// What the relay shows of its state: the groups and devices it holds.
	// A group's records and period are checked from inside by the relay's
	// own tests (member/src/relayd/tests.rs).
	state := func() string {
		g, d := r.Stats()
		return fmt.Sprintf("%d groups, %d devices", g, d)
	}
	settled := state
	reg := func(d device) error {
		cfg := MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert },
			Records: func() []group.Record { return d.records }}
		if d.cred != nil {
			cfg.Credentialed = credOf(d)
		}
		tc, _, _, err := register(ctx, cfg)
		if err == nil {
			t.Cleanup(func() { tc.Close() })
		}
		return err
	}
	// A device of a group the relay holds no device of, whose own records
	// revoke its certificate: the relay keeps nothing of them, and the
	// bytes they cost its source are given back.
	gone := newGroup(t)
	goneRecs := deviceRecords(t, gone, 2)
	self := listedDevice(t, gone, goneRecs)
	revoke := grouptest.Sign(t, group.RecordBody{Type: group.RecordRevoke, Group: group.Tag(gone.Cert), TimeMS: time.Now().UnixMilli(),
		Keys: []group.KeyHash{group.KeyHashOf(self.cert.Leaf)}}, gone.Key)
	self.records = append(goneRecs, revoke)
	before := state()
	if err := reg(self); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Errorf("a device its own records remove: %v, want a refusal for %q", err, "removed")
	}
	if after := settled(); after != before {
		t.Errorf("a device its own records remove changed the relay\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// A group that sends records, a group with credentials, and one more
	// with two devices: the relay serves as many groups as it may, and all
	// registrations come from 127.0.0.1, at its limit too.
	a := newGroup(t)
	aRecs := deviceRecords(t, a, 2)
	a1 := listedDevice(t, a, aRecs)
	a1.records = aRecs
	c := newCredGroup(t)
	c1, c1Key := c.device(t)
	c.sign(t, 1, c1Key, c.key, []device{c1}, &c1)
	b := newGroup(t)
	for _, d := range []device{a1, c1, newDevice(t, b), newDevice(t, b)} {
		if err := reg(d); err != nil {
			t.Fatal(err)
		}
	}

	// A newer members' credential that keeps the first device.
	c4, _ := c.device(t)
	c.sign(t, 2, c1Key, c1Key, []device{c1, c4}, &c4)
	// Credentials of the same tag under another period key.
	rogue := c
	rogue.key, _ = group.NewKey()
	c3, _ := rogue.device(t)
	rogue.sign(t, 5, rogue.key, rogue.key, []device{c3}, &c3)
	// A group of its own with credentials.
	e := newCredGroup(t)
	e1, e1Key := e.device(t)
	e.sign(t, 1, e1Key, e.key, []device{e1}, &e1)
	// A device of the first group with new records of it.
	more := deviceRecords(t, a, 3)
	a2 := listedDevice(t, a, more)
	a2.records = append(slices.Clip(a1.records), more...)
	// A device with the first device's WireGuard key.
	thief := newDevice(t, a)
	thief.key = a1.key
	// A device of a new group with records.
	dg := newGroup(t)
	dRecs := deviceRecords(t, dg, 1)
	d1 := listedDevice(t, dg, dRecs)
	d1.records = dRecs

	for _, tc := range []struct {
		name string
		d    device
		why  string
	}{
		{"a newer members' credential", c4, "this network"},
		{"another period key", c3, "first"},
		{"a group of its own with credentials", e1, "as many groups"},
		{"new records of a registered group", a2, "this network"},
		{"another device's WireGuard key", thief, "another device"},
		{"a group of its own with records", d1, "as many groups"},
	} {
		before := state()
		if err := reg(tc.d); err == nil || !strings.Contains(err.Error(), tc.why) {
			t.Errorf("%s: %v, want a refusal for %q", tc.name, err, tc.why)
			continue
		}
		if after := settled(); after != before {
			t.Errorf("%s: a refused registration changed the relay\nbefore:\n%s\nafter:\n%s", tc.name, before, after)
		}
	}

	// A members' credential that leaves the first device out makes room
	// for its own device, and the period stays the period key's.
	c2, _ := c.device(t)
	c.sign(t, 3, c1Key, c1Key, []device{c2}, &c2)
	if err := reg(c2); err != nil {
		t.Fatalf("a device in place of the one its credential leaves out: %v", err)
	}
	if _, n := r.Stats(); n != 4 {
		t.Errorf("after the newer credential the relay holds %d devices, want 4", n)
	}
	if err := reg(c3); err == nil || !strings.Contains(err.Error(), "first") {
		t.Errorf("another period key after the group's devices changed: %v", err)
	}
}
