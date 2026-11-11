// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

func TestSyncOnOff(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	if _, err := a.do(t, control.Header{Op: control.OpSync, On: control.Bool(false)}, ""); err == nil {
		t.Error("a device in no group turned sync off")
	}
	pairWith(t, a, b)
	for _, s := range []*testService{a, b} {
		if m := s.status(t).Mode; m != "shared" {
			t.Fatalf("%s: a new device's mode is %q, want shared (sync on)", s.name, m)
		}
	}
	waitFor(t, "a connected to b", func() bool { return len(a.status(t).Peers) == 1 })

	if _, err := b.do(t, control.Header{Op: control.OpSync}, ""); err == nil {
		t.Error("sync took a request without on")
	}
	m, err := b.do(t, control.Header{Op: control.OpSync, On: control.Bool(false)}, "")
	if err != nil || !m.SyncOff || m.SyncOffMS != 0 || b.status(t).Mode != "own" {
		t.Fatalf("sync off: %v, %+v", err, m)
	}
	// A deliberate copy reaches the group with sync off, and cbb paste on
	// the other device prints the group's text.
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "from beta"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has beta's text", func() bool { return a.paste(t) == "from beta" })
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from alpha"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta prints the group's text", func() bool { return b.paste(t) == "from alpha" })

	// Sync off is saved, and the others see it in the hello after a restart.
	b.stop()
	b = restartService(t, &h, b)
	if m := b.status(t).Mode; m != "own" {
		t.Fatalf("after a restart the mode is %q", m)
	}
	waitFor(t, "alpha sees beta's sync off", func() bool {
		for _, d := range a.devices(t) {
			if d.Name == "beta" && d.Mode == "own" {
				return true
			}
		}
		return false
	})
	for _, d := range b.devices(t) {
		if d.Self && d.Mode != "own" {
			t.Errorf("beta lists its own mode as %q", d.Mode)
		}
	}

	// Off for a while: the status says until when, and sync on removes the file.
	m, err = b.do(t, control.Header{Op: control.OpSync, On: control.Bool(false), ForMS: time.Hour.Milliseconds()}, "")
	if err != nil || !m.SyncOff || m.SyncOffMS <= 0 || m.SyncOffMS > time.Hour.Milliseconds() || b.status(t).SyncUntilMS == 0 {
		t.Fatalf("sync off for an hour: %v, %+v", err, m)
	}
	if _, err := b.do(t, control.Header{Op: control.OpSync, On: control.Bool(false), ForMS: 31 * 24 * time.Hour.Milliseconds()}, ""); err == nil {
		t.Error("sync off for 31 days was taken")
	}
	if m, err := b.do(t, control.Header{Op: control.OpSync, On: control.Bool(true)}, ""); err != nil || m.SyncOff || b.status(t).Mode != "shared" {
		t.Fatalf("sync on: %v, %+v", err, m)
	}
	if _, err := os.Stat(filepath.Join(b.dir, syncFile)); !os.IsNotExist(err) {
		t.Errorf("sync on left %s: %v", syncFile, err)
	}
}

// TestSyncOffForAWhileTurnsOn restarts a device whose time off passed
// meanwhile: sync is on again.
func TestSyncOffForAWhileTurnsOn(t *testing.T) {
	var h hub
	s := startService(t, &h, "pi")
	if _, err := s.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	s.stop()
	data := fmt.Sprintf(`{"off":true,"until_ms":%d}`, time.Now().Add(-time.Minute).UnixMilli())
	if err := os.WriteFile(filepath.Join(s.dir, syncFile), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	s = restartService(t, &h, s)
	if m := s.status(t).Mode; m != "shared" {
		t.Errorf("sync off whose time passed is still off: mode %q", m)
	}
	// muted answers as sync does, in the phone's member's form, on the
	// socket for everyone.
	plain := func(h control.Header) (*control.Message, error) {
		c, err := control.Dial(s.socket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(20 * time.Second))
		return c.Do(&control.Message{Header: h})
	}
	if m, err := plain(control.Header{Op: control.OpMuted}); err != nil || m.SyncOff || m.Muted {
		t.Fatalf("muted: %v, %+v", err, m)
	}
	m, err := plain(control.Header{Op: control.OpSync, On: control.Bool(false), ForMS: time.Minute.Milliseconds()})
	if err != nil || !m.SyncOff || m.SyncOffMS <= 0 || m.SyncOffMS > time.Minute.Milliseconds() {
		t.Fatalf("sync off for a minute: %v, %+v", err, m)
	}
	if m, err := plain(control.Header{Op: control.OpMuted}); err != nil || !m.SyncOff || m.SyncOffMS <= 0 {
		t.Fatalf("muted after sync off: %v, %+v", err, m)
	}
}

func TestAdminTurnsSync(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b) // alpha is the root
	waitFor(t, "a connected to b", func() bool { return len(a.status(t).Peers) == 1 })

	if _, err := a.do(t, control.Header{Op: control.OpSync, Device: "beta", On: control.Bool(false)}, ""); err != nil {
		t.Fatal(err)
	}
	if m := b.status(t).Mode; m != "own" {
		t.Fatalf("beta's mode is %q, want own", m)
	}
	if _, err := a.do(t, control.Header{Op: control.OpSync, Device: "beta", On: control.Bool(false), ForMS: 1000}, ""); err == nil {
		t.Error("an admin turned another device's sync off for a while")
	}
	// A member that is no admin turns only its own sync.
	if _, err := b.do(t, control.Header{Op: control.OpSync, Device: "alpha", On: control.Bool(false)}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("a member turned the root's sync off: %v", err)
	}
	if m := a.status(t).Mode; m != "shared" {
		t.Errorf("alpha's mode is %q", m)
	}
	// The root names itself: its own sync changes.
	if _, err := a.do(t, control.Header{Op: control.OpSync, Device: "alpha", On: control.Bool(false)}, ""); err != nil || a.status(t).Mode != "own" {
		t.Errorf("the root's own sync: %v, %q", err, a.status(t).Mode)
	}
	// alpha may not have seen the connection end yet; then it ends while
	// alpha waits for the result.
	b.stop()
	if _, err := a.do(t, control.Header{Op: control.OpSync, Device: "beta", On: control.Bool(true)}, ""); err == nil ||
		!strings.Contains(err.Error(), "not connected") && !strings.Contains(err.Error(), "closed before it answered") {
		t.Errorf("sync on for a device that is off: %v", err)
	}
}
