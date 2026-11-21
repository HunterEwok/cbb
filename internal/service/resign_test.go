// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/control"
)

// TestRestoredAdminSignsAgain plays an admin computer brought back from an
// old backup while the rest of the group is away: it signs with a seq it
// signed already, the root sees two histories, voids both with cbb resolve,
// and the admin signs again by itself what it signed since the backup,
// here a table of main hubs,
// (docs/protocol.md, section 10, "Going on after two histories").
func TestRestoredAdminSignsAgain(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	makeAdmin(t, pi, a)

	// The admin's state as a backup keeps it: the group's records and the
	// log of the records it signed (records06File, signed06File).
	backup := map[string][]byte{}
	for _, f := range []string{records06File, signed06File} {
		data, err := os.ReadFile(filepath.Join(a.dir, f))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		backup[f] = data
	}
	aID, piID := a.status(t).Device, pi.status(t).Device
	// The hubs record of s's records: the devices it names.
	hubs := func(s *testService) []string {
		var out []string
		for _, d := range s.devices(t) {
			if d.Hub {
				out = append(out, d.ID)
			}
		}
		return out
	}
	only := func(s *testService, id string) func() bool {
		return func() bool {
			hs := hubs(s)
			return len(hs) == 1 && hs[0] == id
		}
	}
	// The table after the backup names the root, the one after the
	// restore names the admin.
	if hs := hubs(pi); len(hs) != 0 {
		t.Fatalf("the group has hubs before any table: %v", hs)
	}
	if _, err := a.do(t, control.Header{Op: control.OpHubs, Hubs: []string{piID}}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the root holds the hubs table", only(pi, piID))

	a.stop()
	pi.stop()
	b.stop()
	for f, data := range backup {
		path := filepath.Join(a.dir, f)
		if data == nil {
			os.Remove(path)
		} else if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a = restartService(t, &h, a)
	if _, err := a.do(t, control.Header{Op: control.OpHubs, Hubs: []string{aID}}, ""); err != nil {
		t.Fatal(err)
	}
	pi = restartService(t, &h, pi)
	b = restartService(t, &h, b)
	waitFor(t, "the root sees two histories", func() bool {
		for _, c := range pi.status(t).Conflicts {
			if c.Kind == authority.ConflictTwoHistories {
				return true
			}
		}
		return false
	})
	if _, err := a.do(t, control.Header{Op: control.OpResolve}, ""); err == nil {
		t.Error("an admin resolved two histories")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpResolve}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the admin signs its hubs table again and the group goes on", func() bool {
		st := pi.status(t)
		return (st.Stop == "" || st.Stop == authority.StopNone) && len(st.Conflicts) == 0 && only(pi, aID)() && only(b, aID)()
	})
	if !a.logged("signed 1 of its records again") {
		t.Error("the admin did not say it signed its record again")
	}
}
