// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority_test

import (
	"fmt"
	"testing"

	"github.com/HunterEwok/cbb/internal/authority"
)

// ignoredWhy returns why record id is listed as ignored, "" when it is not.
func ignoredWhy(s *authority.State, id authority.Hash) string {
	for _, g := range s.Ignored {
		if g.Record == id {
			return g.Why
		}
	}
	return ""
}

// TestDeviceLimit: an admin's devices come after the root's, whatever the
// order they were signed in, and the devices past MaxDevices count for
// nothing; the admin's first devices, in its own order, are the ones kept.
func TestDeviceLimit(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "member", computerPowers)
	var byC []authority.Record
	for i := range 10 {
		byC = append(byC, w.device("C", fmt.Sprintf("c%d", i), "member", nil, nil, false))
	}
	// rootphone, C and these: 252 devices of the root.
	for i := range authority.MaxDevices - 6 {
		w.device("root", fmt.Sprintf("r%d", i), "member", nil, nil, false)
	}
	s := w.evalAll(nil)
	if len(s.Devices) != authority.MaxDevices || s.Stop != "none" {
		t.Fatalf("%d devices, want %d; stop %q", len(s.Devices), authority.MaxDevices, s.Stop)
	}
	for i, r := range byC {
		in := findDevice(s, w.ids[fmt.Sprintf("c%d", i)]) != nil
		if in != (i < 4) {
			t.Errorf("C's device %d counts: %v", i, in)
		}
		if why := ignoredWhy(s, r.ID()); i >= 4 && why != authority.WhyLimit && len(s.Ignored) < authority.MaxIgnored {
			t.Errorf("C's device %d ignored for %q", i, why)
		}
	}
}

// TestAdminLimit: the admin keys a root names past MaxAdmins count for
// nothing, and the device record naming one does not count at all.
func TestAdminLimit(t *testing.T) {
	w := newWorld(t)
	for i := range authority.MaxAdmins + 1 {
		w.makeAdmin(fmt.Sprintf("A%d", i), "member", computerPowers)
	}
	last := fmt.Sprintf("A%d", authority.MaxAdmins)
	s := w.evalAll(nil)
	admins := 0
	for _, d := range s.Devices {
		if d.Admin != nil {
			admins++
		}
	}
	if admins != authority.MaxAdmins || findDevice(s, w.ids[last]) != nil {
		t.Fatalf("%d admins, want %d; the last one listed: %v", admins, authority.MaxAdmins, findDevice(s, w.ids[last]) != nil)
	}
	if why := ignoredWhy(s, w.byName["device "+last+" by root"].ID()); why != authority.WhyLimit {
		t.Errorf("the last admin's device record ignored for %q", why)
	}
	// It admits nothing: its key is no admin.
	r := w.device(last, "late", "member", nil, nil, false)
	s = w.eval(w.recs, nil)
	if findDevice(s, w.ids["late"]) != nil || ignoredWhy(s, r.ID()) != authority.WhyPower {
		t.Fatalf("the device the last admin admitted counts: %s", mustEncode(t, s))
	}
}

// TestPathLimit: a handover that would put more than MaxPath roots on the
// path is void; the ones before it took effect.
func TestPathLimit(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A1", "phone", phonePowers)
	first := map[authority.Hash]int64{}
	var claims []authority.Record
	for i := 1; i <= authority.MaxPath; i++ {
		admin, next := fmt.Sprintf("A%d", i), fmt.Sprintf("R%d", i+1)
		c := w.claim(admin, next, nil)
		first[c.ID()] = int64(i-1) * authority.DefaultDelay
		claims = append(claims, c)
		w.device(next, admin, "phone", nil, nil, true)
		if i < authority.MaxPath {
			na := fmt.Sprintf("A%d", i+1)
			w.admin(na, next)
			w.device(next, na, "phone", phonePowers, authority.Commands, false)
		}
	}
	w.now = int64(authority.MaxPath) * authority.DefaultDelay
	s := w.evalAll(first)
	if len(s.Roots) != authority.MaxPath {
		t.Fatalf("%d roots, want %d: %s", len(s.Roots), authority.MaxPath, mustEncode(t, s))
	}
	for i, c := range claims {
		want := "effective"
		if i == len(claims)-1 {
			want = "void"
		}
		if got := claimState(s, c.ID()); got != want {
			t.Errorf("claim %d is %q, want %q", i+1, got, want)
		}
	}
	if s.RootDevice != w.ids[fmt.Sprintf("A%d", authority.MaxPath-1)] {
		t.Errorf("the root device is %q", s.RootDevice)
	}
}

// TestRecordLimit: records past MaxRecords count for nothing, the root's
// before an admin's, and the root's checkpoint brings the set back under
// the limit, though the checkpoint itself is past it in the full set.
func TestRecordLimit(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "member", computerPowers)
	// rootphone, C and these: the root's last 8 records are past the limit.
	for i := 1; i <= authority.MaxRecords+6; i++ {
		w.sign(fmt.Sprintf("settings %d", i), "root", authority.Body{Type: authority.TypeSettings, TakeoverDelayMS: ptr(int64(i))}, nil)
	}
	laptop := w.device("C", "laptop", "member", nil, nil, false)
	s := w.evalAll(nil)
	if s.Stop != "none" || findDevice(s, w.ids["laptop"]) != nil || findDevice(s, w.ids["C"]) == nil {
		t.Fatalf("the admin's record past the limit counts: %s", mustEncode(t, s))
	}
	if why := ignoredWhy(s, laptop.ID()); why != authority.WhyLimit && len(s.Ignored) < authority.MaxIgnored {
		t.Errorf("the laptop's record ignored for %q", why)
	}
	if got := w.byName[fmt.Sprintf("settings %d", authority.MaxRecords+6)].ID(); ignoredWhy(s, got) != authority.WhyLimit && len(s.Ignored) < authority.MaxIgnored {
		t.Errorf("the root's last settings is not past the limit")
	}

	cp := w.checkpoint("root", w.byName["device rootphone by root"], w.byName["device C by root"], laptop)
	s = w.evalAll(nil)
	if s.Checkpoint == nil || *s.Checkpoint != cp.ID() || findDevice(s, w.ids["laptop"]) == nil {
		t.Fatalf("the checkpoint should bring the set under the limit: %s", mustEncode(t, s))
	}
}

// TestSetBytesLimit: records past MaxSetBytes count for nothing, though
// they are fewer than MaxRecords. (Not a vector: the set is over a
// megabyte.)
func TestSetBytesLimit(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "member", computerPowers)
	// Resolve records naming records nobody has, about 7.5 KB each.
	n := 0
	for size := 0; size <= authority.MaxSetBytes; n++ {
		var ids []authority.Hash
		for j := range 115 {
			var h authority.Hash
			h[0], h[1], h[2] = byte(n), byte(n>>8), byte(j)
			ids = append(ids, h)
		}
		r := w.sign(fmt.Sprintf("resolve %d", n), "root", authority.Body{Type: authority.TypeResolve, Records: ids}, nil)
		size += len(r.Body) + len(r.Sig)
	}
	if n >= authority.MaxRecords {
		t.Fatalf("%d records, the bytes should run out first", n)
	}
	laptop := w.device("C", "laptop", "member", nil, nil, false)
	s := w.eval(w.recs, nil)
	if findDevice(s, w.ids["laptop"]) != nil || findDevice(s, w.ids["C"]) == nil {
		t.Fatalf("the admin's record past the limit counts: %s", mustEncode(t, s))
	}
	if why := ignoredWhy(s, laptop.ID()); why != authority.WhyLimit && len(s.Ignored) < authority.MaxIgnored {
		t.Errorf("the laptop's record ignored for %q", why)
	}
}
