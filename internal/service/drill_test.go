// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// The recovery drills (docs/testing.md, "Recovery drills"; tools/e2e/drills.sh
// runs them with TestRecovery and TestFFIPhoneRestore): what a person does
// after a loss, played on whole members. A device restored from yesterday's
// backup gets back in; a removed device restored from a backup made before
// its removal stays out. The root lost and taken back with the recovery key
// is TestRecovery (computers) and TestFFIPhoneRestore (a phone).

// backup copies a stopped service's state folder, as a nightly backup.
func backup(t *testing.T, s *testService) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(s.dir, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(to, 0o700)
		case d.Type()&fs.ModeSocket != 0, !d.Type().IsRegular():
			return nil // the control sockets are the running service's
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// restore puts a backup in place of a stopped service's state folder.
func restore(t *testing.T, s *testService, from string) {
	t.Helper()
	if err := os.RemoveAll(s.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(s.dir, os.DirFS(from)); err != nil {
		t.Fatal(err)
	}
}

// TestDrillRestoreFromYesterday: the laptop's disk is lost and its state
// comes back from the backup of the day before, while the group went on:
// a device joined, one was removed. The laptop starts from the backup,
// learns what changed and syncs both ways again.
func TestDrillRestoreFromYesterday(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	laptop := startService(t, &h, "laptop")
	old := startService(t, &h, "old")
	pairWith(t, pi, laptop)
	pairWith(t, pi, old)
	waitFor(t, "the laptop meets both", func() bool { return len(laptop.status(t).Peers) == 2 })
	laptop.stop()
	yesterday := backup(t, laptop)
	laptop = restartService(t, &h, laptop)

	// A day of the group's life without the backup.
	desk := startService(t, &h, "desk")
	pairWith(t, pi, desk)
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "old"}, ""); err != nil {
		t.Fatal(err)
	}
	old.stop()
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "today"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the laptop has today's copy", func() bool { return laptop.paste(t) == "today" })

	// The disk is lost: yesterday's state comes back.
	laptop.stop()
	restore(t, laptop, yesterday)
	laptop = restartService(t, &h, laptop)
	waitUpTo(t, 60*time.Second, "the restored laptop meets the pi and the new desk, not the removed device", func() bool {
		st := laptop.status(t)
		if len(st.Peers) != 2 {
			return false
		}
		names := map[string]bool{}
		for _, p := range st.Peers {
			names[p.Name] = true
		}
		return names["pi"] && names["desk"] && !names["old"]
	})
	if _, err := desk.do(t, control.Header{Op: control.OpCopy}, "after the restore"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the restored laptop has the desk's copy", func() bool { return laptop.paste(t) == "after the restore" })
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "from the restored laptop"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has the restored laptop's copy", func() bool { return pi.paste(t) == "from the restored laptop" })
}

// TestDrillRemovedStaysOut: a removed device, its state put back from a
// backup made before the removal, starts again and stays out: the group's
// devices do not sync with it, and it gets none of their copies.
func TestDrillRemovedStaysOut(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	laptop := startService(t, &h, "laptop")
	lost := startService(t, &h, "lost")
	pairWith(t, pi, laptop)
	pairWith(t, pi, lost)
	waitFor(t, "the lost device meets both", func() bool { return len(lost.status(t).Peers) == 2 })
	lost.stop()
	before := backup(t, lost)
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "lost"}, ""); err != nil {
		t.Fatal(err)
	}
	// The laptop learns the removal while the lost device is away.
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "after the removal"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the laptop has the copy after the removal", func() bool { return laptop.paste(t) == "after the removal" })

	restore(t, lost, before)
	lost = restartService(t, &h, lost)
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "not for the lost device"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the laptop has the new copy", func() bool { return laptop.paste(t) == "not for the lost device" })
	// Long enough for discovery, a dial and a sync to have happened.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if got := lost.paste(t); got == "not for the lost device" {
			t.Fatal("the removed device got a copy of the group")
		}
		for _, s := range []*testService{pi, laptop} {
			for _, p := range s.status(t).Peers {
				if p.Name == "lost" {
					t.Fatalf("%s syncs with the removed device", s.name)
				}
			}
		}
		time.Sleep(time.Second)
	}
}
