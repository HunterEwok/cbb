// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/remotepaste"
)

// leaveOn runs leave on s and waits for its service to end, as it does to
// be started again in no group.
func leaveOn(t *testing.T, s *testService) {
	t.Helper()
	if _, err := s.do(t, control.Header{Op: control.OpLeave}, ""); err != nil {
		t.Fatalf("leave on %s: %v", s.name, err)
	}
	select {
	case err := <-s.done:
		if !errors.Is(err, ErrLeft) {
			t.Fatalf("%s ended with %v after leave", s.name, err)
		}
		s.cancel = nil
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not restart after leave", s.name)
	}
}

// TestLeave: a member leaves its group and keeps its settings; a member
// the group removed leaves and joins again; the root leaves only alone.
func TestLeave(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "the deck lists the pi", func() bool { return listed(deck.devices(t)) == "deck pi" })

	if _, err := pi.do(t, control.Header{Op: control.OpLeave}, ""); err == nil || !strings.Contains(err.Error(), "cbb handover") {
		t.Errorf("the root left a group with other devices: %v", err)
	}

	// The deck's settings: remote paste and an action on go off, the mode stays.
	if err := remotepaste.Save(deck.dir, remotepaste.Settings{On: true}); err != nil {
		t.Fatal(err)
	}
	set := actions.Settings{}
	set.Set(actions.Action{Name: actions.Lock, On: true})
	if err := actions.Save(deck.dir, set); err != nil {
		t.Fatal(err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpMode, Name: "own"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRevoke, Name: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck sees it was removed", func() bool { return deck.status(t).Removed })

	leaveOn(t, deck)
	for _, name := range groupFiles {
		if _, err := os.Stat(filepath.Join(deck.dir, name)); err == nil {
			t.Errorf("%s is left after leave", name)
		}
	}
	if s, _ := remotepaste.Load(deck.dir); s.On {
		t.Error("remote paste stayed on")
	}
	if s, _ := actions.Load(deck.dir); len(s.On()) != 0 {
		t.Errorf("actions stayed on: %v", s.On())
	}
	if _, err := os.Stat(filepath.Join(deck.dir, modeFile)); err != nil {
		t.Errorf("the mode went: %v", err)
	}

	deck = restartService(t, &h, deck)
	if st := deck.status(t); st.Group != "" {
		t.Fatalf("in group %s after leave", st.Group)
	}
	pairWith(t, pi, deck)
	waitFor(t, "the deck is back", func() bool { return listed(pi.devices(t)) == "deck pi" && !deck.status(t).Removed })

	// Alone, the root leaves, and the group is gone.
	if _, err := pi.do(t, control.Header{Op: control.OpRevoke, Name: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi is alone", func() bool { return listed(pi.devices(t)) == "pi" })
	leaveOn(t, pi)
	if _, err := group.Load(pi.dir); !errors.Is(err, group.ErrNoGroup) {
		t.Errorf("the root's group after leave: %v", err)
	}
}

// TestLeaveDamaged: a device whose group file is damaged leaves, which
// lets it join again.
func TestLeaveDamaged(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	pi.stop()
	if err := os.WriteFile(filepath.Join(pi.dir, group.FileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	pi = restartService(t, &h, pi)
	if _, err := pi.do(t, control.Header{Op: control.OpStatus}, ""); err == nil || !strings.Contains(err.Error(), "cbb leave") {
		t.Fatalf("status with a damaged file: %v", err)
	}
	leaveOn(t, pi)
	pi = restartService(t, &h, pi)
	if _, err := pi.do(t, control.Header{Op: control.OpLeave}, ""); err == nil || !strings.Contains(err.Error(), "nothing to leave") {
		t.Errorf("leave in no group: %v", err)
	}
}

// TestLiteLeave: a lite member the group removed leaves through its
// service, which then stops to be started again; with the service stopped,
// cbb leave looks at the files itself and finds no group. CBB_LITE names
// the lite member's binary (cargo build at the top).
func TestLiteLeave(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
	lite := startLite(t, bin, dir, "-no-mdns", "-peer", pi.addr())
	waitFor(t, "the lite member connects", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := pi.do(t, control.Header{Op: control.OpRevoke, Name: "lite"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member sees it was removed", func() bool {
		m, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status != nil && m.Status.Removed
	})
	leave := func() string {
		out, err := exec.Command(bin, "-state", dir, "-socket", lite.socket, "leave", "-yes").CombinedOutput()
		if err != nil {
			t.Fatalf("cbb leave: %v; %s", err, out)
		}
		return string(out)
	}
	if out := leave(); !strings.Contains(out, "restarts in no group") {
		t.Errorf("cbb leave through the service: %s", out)
	}
	select {
	case <-lite.done:
		lite.cancel = nil
	case <-time.After(10 * time.Second):
		t.Fatal("the lite member did not restart after leave")
	}
	for _, name := range []string{"identity.json", "records.json", "seal.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s is left", name)
		}
	}
	if out, err := exec.Command(bin, "-state", dir, "-socket", lite.socket, "leave", "-yes").CombinedOutput(); err == nil || !strings.Contains(string(out), "nothing to leave") {
		t.Errorf("leave in no group: %v; %s", err, out)
	}
}
