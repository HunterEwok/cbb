// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/budget"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
)

// settled is the relay's state once the registrations it refused have
// ended: a refusal reaches the client while its registration still holds
// its group's turn to check records, which it gives back as it returns.
func (r *Relay) settled(t *testing.T) string {
	t.Helper()
	waitFor(t, "the refused registrations to end", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.tagLocks) == 0
	})
	return r.state()
}

// state is what a relay holds of its groups and devices, as text that two
// moments compare by: the charges a registration pays for its setup are
// left out, since they are what a refused one costs.
func (r *Relay) state() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var lines []string
	for tag, g := range r.groups {
		for dev, m := range g {
			lines = append(lines, fmt.Sprintf("member %s %s %p %s", tag, dev, m, m.addr))
		}
	}
	for a, m := range r.byAddr {
		lines = append(lines, fmt.Sprintf("addr %s %p", a, m))
	}
	for tag, p := range r.periods {
		lines = append(lines, fmt.Sprintf("period %s %x %d %d %x", tag, p.signer, p.hubs, p.membersVer, p.members))
	}
	for tag, rs := range r.records {
		lines = append(lines, fmt.Sprintf("records %s %d %d %s", tag, rs.set.Len(), rs.bytes, rs.set.Digest()))
	}
	for tag := range r.tagLocks {
		lines = append(lines, "lock "+tag)
	}
	for t := range r.calls {
		lines = append(lines, "call "+t)
	}
	slices.Sort(lines)
	return fmt.Sprintf("%s\nheld:\n%s\nrecord bytes:\n%s", strings.Join(lines, "\n"), r.held, r.recordBytes)
}

// A registration the relay refuses leaves it as it was: whatever the
// reason, it keeps nothing of the refused device's group, its period or
// records, and the devices registered before stay as they were.
func TestRefusedRegistrationLeavesState(t *testing.T) {
	r, link := startAny(t, Config{Open: true, Limits: Limits{Groups: 3, PerAddress: 4}})
	ctx := context.Background()
	// Only this package's relay shows its state; the Rust one is checked
	// for the refusals.
	gr := goRelay(r)
	state := func() string {
		if gr == nil {
			return ""
		}
		return gr.state()
	}
	settled := func() string {
		if gr == nil {
			return ""
		}
		return gr.settled(t)
	}
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
	if gr != nil {
		gr.mu.Lock()
		_, keeps := gr.records[group.Tag(gone.Cert)]
		held := gr.recordBytes.Held(netip.MustParseAddr("127.0.0.1"), budget.Address)
		gr.mu.Unlock()
		if keeps || held != 0 {
			t.Errorf("after a device its own records remove the relay keeps its records %v and %d bytes of its source", keeps, held)
		}
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
	if gr != nil {
		gr.mu.Lock()
		g := gr.groups[credentialTag(c.body.Tag)]
		_, kept := g[c1.id]
		_, joined := g[c2.id]
		gr.mu.Unlock()
		if kept || !joined {
			t.Errorf("after the newer credential the relay holds the first device %v and the new one %v", kept, joined)
		}
	} else if _, n := r.Stats(); n != 4 {
		t.Errorf("after the newer credential the relay holds %d devices, want 4", n)
	}
	if err := reg(c3); err == nil || !strings.Contains(err.Error(), "first") {
		t.Errorf("another period key after the group's devices changed: %v", err)
	}
}
