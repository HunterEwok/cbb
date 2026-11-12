// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority_test

import (
	"slices"
	"testing"

	"github.com/HunterEwok/cbb/internal/authority"
)

// hubs signs a hubs record by signer naming the devices by name, at time
// ms.
func (w *world) hubs(name, signer string, ms int64, devices ...string) authority.Record {
	b := authority.Body{Type: authority.TypeHubs, TimeMS: ms}
	for _, d := range devices {
		id, ok := w.ids[d]
		if !ok {
			id = d
		}
		b.Hubs = append(b.Hubs, id)
	}
	return w.sign(name, signer, b, nil)
}

func (w *world) wantHubs(s *authority.State, names ...string) {
	w.t.Helper()
	var want []string
	for _, n := range names {
		want = append(want, w.ids[n])
	}
	if !slices.Equal(s.Hubs, want) {
		w.t.Fatalf("hubs %v, want %v (%v): %s", s.Hubs, want, names, mustEncode(w.t, s))
	}
}

// TestHubsTable: the hubs record that counts gives the state's hubs: a
// root's beats an admin's whatever its time, an admin's needs the power
// hub, between admins the later time wins, and only the devices of the
// state with the role full or phone are kept, in the table's order.
func TestHubsTable(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "member", computerPowers)
	w.makeAdmin("D", "member", []string{authority.PowerAdmit})
	w.makeAdmin("E", "member", computerPowers)
	w.device("root", "pi", "board", nil, nil, false)
	w.device("root", "desk", "member", nil, nil, false)
	if s := w.evalAll(nil); s.Hubs != nil {
		t.Fatalf("hubs without a table: %v", s.Hubs)
	}

	// A member without the cap hub and a device the group does not have are left out.
	w.hubs("hubs by C", "C", 10, "E", "pi", "0123456789abcdef0123456789abcdef", "rootphone", "C")
	w.wantHubs(w.evalAll(nil), "E", "rootphone", "C")

	// An admin without the power hub: its table does not count.
	byD := w.hubs("hubs by D", "D", 20, "D")
	s := w.evalAll(nil)
	w.wantHubs(s, "E", "rootphone", "C")
	if why := ignoredWhy(s, byD.ID()); why != authority.WhyPower {
		t.Errorf("D's table ignored for %q", why)
	}

	// A later admin table wins, an earlier one does not.
	w.hubs("hubs by E", "E", 5, "E")
	w.wantHubs(w.evalAll(nil), "E", "rootphone", "C")
	w.hubs("hubs by E later", "E", 30, "desk", "E")
	w.wantHubs(w.evalAll(nil), "desk", "E")

	// The root's table wins, though older by its clock.
	w.hubs("hubs by root", "root", 1, "C", "rootphone")
	w.wantHubs(w.evalAll(nil), "C", "rootphone")

	// A removed device leaves the table; the table stays.
	w.sign("revoke C", "root", revoke(w.members["C"], w.adminKey("C")), nil)
	w.wantHubs(w.evalAll(nil), "rootphone")
}
