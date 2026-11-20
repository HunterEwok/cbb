// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
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

	// The deck's settings: remote paste and an action on go off, sync off stays.
	if err := remotepaste.Save(deck.dir, remotepaste.Settings{On: true}); err != nil {
		t.Fatal(err)
	}
	set := actions.Settings{}
	set.Set(actions.Action{Name: actions.Lock, On: true})
	if err := actions.Save(deck.dir, set); err != nil {
		t.Fatal(err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpSync, On: control.Bool(false)}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "deck"}, ""); err != nil {
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
	if _, err := os.Stat(filepath.Join(deck.dir, syncFile)); err != nil {
		t.Errorf("sync off went: %v", err)
	}

	deck = restartService(t, &h, deck)
	if st := deck.status(t); st.Group != "" {
		t.Fatalf("in group %s after leave", st.Group)
	}
	pairWith(t, pi, deck)
	waitFor(t, "the deck is back", func() bool { return listed(pi.devices(t)) == "deck pi" && !deck.status(t).Removed })

	// Alone, the root leaves, and the group is gone.
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "deck"}, ""); err != nil {
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

// TestAloneLeave: a small device the group removed leaves through its
// service, which then stops to be started again; with the service stopped,
// cbb leave looks at the files itself and finds no group. CBB_TEST_ALONE names
// the small device's binary (cargo build at the top).
func TestAloneLeave(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinAlone(t, bin, pi)
	small := startAlone(t, bin, dir, "-no-mdns", "-peer", pi.addr())
	waitFor(t, "the small device connects", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "small"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device sees it was removed", func() bool {
		m, err := small.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status != nil && m.Status.Removed
	})
	leave := func() string {
		out, err := exec.Command(bin, "-state", dir, "-socket", small.socket, "leave", "-yes").CombinedOutput()
		if err != nil {
			t.Fatalf("cbb leave: %v; %s", err, out)
		}
		return string(out)
	}
	if out := leave(); !strings.Contains(out, "restarts in no group") {
		t.Errorf("cbb leave through the service: %s", out)
	}
	select {
	case <-small.done:
		small.cancel = nil
	case <-time.After(10 * time.Second):
		t.Fatal("the small device did not restart after leave")
	}
	for _, name := range []string{"identity.json", "records.json", "seal.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s is left", name)
		}
	}
	if out, err := exec.Command(bin, "-state", dir, "-socket", small.socket, "leave", "-yes").CombinedOutput(); err == nil || !strings.Contains(string(out), "nothing to leave") {
		t.Errorf("leave in no group: %v; %s", err, out)
	}
}

// TestRemovedWhileAway: a computer removed while its service was stopped
// hears it was removed when it comes back: the root's connection with it
// carries the records that remove it, then closes, and the other computer
// stays in the group.
func TestRemovedWhileAway(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, deck)
	pairWith(t, pi, laptop)
	waitFor(t, "the deck connected to both others", func() bool { return len(deck.status(t).Peers) == 2 })
	deck.stop()
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the laptop has the removal", func() bool { return listed(laptop.devices(t)) == "laptop pi" })
	if pi.on06() {
		removedWhileAway06(t, &h, pi, laptop, deck)
		return
	}
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck says it was removed", func() bool { return deck.status(t).Removed })
	waitFor(t, "the removed deck keeps no connection", func() bool { return len(deck.status(t).Peers) == 0 })
	if laptop.status(t).Removed || pi.status(t).Removed {
		t.Error("a member the root did not remove says it was removed")
	}
}

// removedWhileAway06 is TestRemovedWhileAway on the records of 0.6, by the
// owner's rule: a removed device need not learn of its removal; the group
// refuses it and gives it no device list. So the members refuse its hello
// and keep no connection with it, no copy crosses either way, and it gets
// no records: its set stays as it was, with the devices it knew.
func removedWhileAway06(t *testing.T, h *hub, pi, laptop, deck *testService) {
	t.Helper()
	set := filepath.Join(deck.dir, "group.cbor")
	before, err := os.ReadFile(set)
	if err != nil {
		t.Fatal(err)
	}
	deck = restartService(t, h, deck)
	deckID := deck.status(t).Device
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "from the removed deck"); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from pi after the removal"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the laptop has pi's copy", func() bool { return laptop.paste(t) == "from pi after the removal" })
	// Long enough for discovery to find the deck and dial it more than once.
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		if n := len(deck.status(t).Peers); n != 0 {
			t.Fatalf("the removed deck has %d connections", n)
		}
		for _, s := range []*testService{pi, laptop} {
			for _, p := range s.status(t).Peers {
				if p.ID == deckID {
					t.Fatalf("%s keeps a connection with the removed deck", s.name)
				}
			}
			if s.paste(t) == "from the removed deck" {
				t.Fatalf("%s took a copy from the removed deck", s.name)
			}
		}
		if deck.paste(t) == "from pi after the removal" {
			t.Fatal("the removed deck got the group's copy")
		}
	}
	after, err := os.ReadFile(set)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the removed deck got records from the group")
	}
	if got := listed(deck.devices(t)); got != "deck laptop pi" {
		t.Errorf("the removed deck lists %q, the devices it knew before", got)
	}
	if laptop.status(t).Removed || pi.status(t).Removed {
		t.Error("a member the root did not remove says it was removed")
	}
}
