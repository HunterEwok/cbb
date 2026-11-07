// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/remotepaste"
)

// joinFull pairs a Rust member with the root's code window as a full
// member named rust and returns its state folder.
func joinFull(t *testing.T, bin string, root *testService) string {
	t.Helper()
	c, code := openWindow(t, root)
	defer c.Close()
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-full", "-name", "rust", "-code", root.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair -full: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on %s ended with %+v, %v", root.name, m, err)
	}
	return dir
}

// TestLiteAdminCommands checks the commands an admin Rust service signs
// for another device: a quick action, a paste, and turning remote paste
// and the quick actions off there, one device or all.
func TestLiteAdminCommands(t *testing.T) {
	bin := liteBin(t)
	cli := goCLI(t)
	var h hub
	runner := &fakeRunner{}
	desk := startService(t, &h, "desk")
	deck := startWith(t, &h, "deck", "linux", func(c *Config) { c.runner = runner })
	pairWith(t, desk, deck)
	dir := joinFull(t, bin, desk)
	rust := startLite(t, bin, dir, "-no-mdns", "-full", "-no-listen", "-peer", desk.addr(), "-peer", deck.addr())
	waitFor(t, "the Rust member connected to both", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 2
	})
	waitFor(t, "the deck has the Rust member", func() bool { return len(deck.status(t).Peers) == 2 })
	if _, err := rust.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: actions.Lock}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("an action from a member that is no admin: %v", err)
	}
	adminOn(t, cli, desk, "rust")
	if _, err := deck.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{{Name: actions.Lock, On: true}}}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust admin locks the deck", func() bool {
		_, err := rust.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: actions.Lock}, "")
		if err != nil && !strings.Contains(err.Error(), "only an admin") {
			t.Fatalf("cbb action lock -on deck: %v", err)
		}
		return err == nil
	})
	if got := runner.took(); !slices.Equal(got, []string{actions.Lock}) {
		t.Errorf("the deck ran %v", got)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpActionOn, Device: "rust", Name: actions.Lock}, ""); err == nil || !strings.Contains(err.Error(), "another device") {
		t.Errorf("an action on itself: %v", err)
	}

	// A paste reaches the deck sealed, whose remote paste is off.
	if _, err := rust.do(t, control.Header{Op: control.OpPasteOn, Device: "deck", Kind: control.KindSecret}, "hello"); err == nil || !strings.Contains(err.Error(), "remote paste is off on this device") {
		t.Errorf("a paste on the deck: %v", err)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpPasteOn, Device: "deck"}, "\x01"); err == nil || !strings.Contains(err.Error(), "nothing to paste") {
		t.Errorf("an empty paste: %v", err)
	}

	// Off on the deck, then on every device.
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpReceive, Name: "off", Device: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	if set, err := remotepaste.Load(deck.dir); err != nil || set.On {
		t.Errorf("remote paste on the deck: %+v, %v", set, err)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpReceive, Name: "on", Device: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "own user") {
		t.Errorf("remote paste on for another device: %v", err)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpActionOff, All: true}, ""); err != nil {
		t.Fatal(err)
	}
	if set, err := actions.Load(deck.dir); err != nil || len(set.On()) != 0 {
		t.Errorf("the deck's actions after cbb action off -all: %v, %v", set.On(), err)
	}
	time.Sleep(time.Second) // one action a second from one sender
	if _, err := rust.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: actions.Lock}, ""); err == nil || !strings.Contains(err.Error(), "is off on this device") {
		t.Errorf("an action turned off: %v", err)
	}
}
