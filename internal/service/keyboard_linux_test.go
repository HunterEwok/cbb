// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package service

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/HunterEwok/cbb/internal/blekeyboard"
	"github.com/HunterEwok/cbb/internal/blekeyboard/bluetest"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/keyboard"
	"github.com/HunterEwok/cbb/internal/peripheral"
)

// TestKeyboard: cbb keyboard on a Linux computer, against a fake BlueZ:
// on, typing, a remote paste sent to the keyboard's host, and off.
func TestKeyboard(t *testing.T) {
	f := bluetest.Start(t)
	var h hub
	pi := startService(t, &h, "pi")
	deck := startEnv(t, &h, "deck", func(c *Config) {
		c.KeyboardBus = func() (*dbus.Conn, error) { return dbus.Connect(f.Addr) }
	}, "DBUS_SYSTEM_BUS_ADDRESS="+f.Addr)
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })

	if k := deck.status(t).Keyboard; k == nil || k.On {
		t.Fatalf("before on: %+v", k)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpKeyboard, Name: "on", Keyboard: &control.Keyboard{Layout: "de"}}, ""); err == nil {
		t.Error("a layout that does not exist was taken")
	}
	m, err := deck.do(t, control.Header{Op: control.OpKeyboard, Name: "on", Keyboard: &control.Keyboard{Layout: "us", Rate: 60, Pastes: true}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if k := m.Status.Keyboard; k == nil || !k.On || k.Layout != "us" || k.Rate != 60 || !k.Pastes || k.Connected {
		t.Fatalf("after on: %+v", k)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpKeyboard, Name: "type"}, "hi"); err == nil || !strings.Contains(err.Error(), "no device is connected") {
		t.Errorf("typing with no host: %v", err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpKeyboard, Name: "pair"}, ""); err != nil {
		t.Fatal(err)
	}
	if k := deck.status(t).Keyboard; k.VisibleUntilMS == 0 {
		t.Errorf("not visible after pair: %+v", k)
	}

	reports, stop := f.Subscribe(t)
	want := func(text string) {
		t.Helper()
		rs, _ := keyboard.US.Reports(text)
		for i, w := range rs {
			select {
			case v := <-reports:
				if !slices.Equal(v, w[:]) {
					t.Fatalf("%q, report %d: %x, want %x", text, i, v, w)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%q, report %d did not come", text, i)
			}
		}
	}
	if _, err := deck.do(t, control.Header{Op: control.OpKeyboard, Name: "type"}, "ok\r\n"); err != nil {
		t.Fatal(err)
	}
	want("ok\n")

	// A remote paste goes to the host, and a line break needs Enter.
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	if p := deck.status(t).Paste; !slices.Contains(p.Targets, peripheral.TargetKeyboard) {
		t.Errorf("the paste targets: %v", p.Targets)
	}
	paste := func(text string) error {
		time.Sleep(time.Second) // one paste a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "deck"}, text)
		return err
	}
	if err := paste("Wi-Fi 42"); err != nil {
		t.Fatal(err)
	}
	want("Wi-Fi 42")
	if err := paste("a\nb"); err == nil || !strings.Contains(err.Error(), "types as Enter") {
		t.Errorf("two lines: %v", err)
	}
	if err := paste("\u043f\u0440\u0438"); err == nil || !strings.Contains(err.Error(), "has no key for") {
		t.Errorf("what the layout cannot type: %v", err)
	}
	stop()

	m, err = deck.do(t, control.Header{Op: control.OpKeyboard, Name: "off"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if k := m.Status.Keyboard; k.On || k.Pastes {
		t.Errorf("after off: %+v", k)
	}
}

// TestKeyboardNoGroup: a computer in no group is a keyboard too, and its
// replies say how the keyboard stands, as cbb keyboard prints them.
func TestKeyboardNoGroup(t *testing.T) {
	f := bluetest.Start(t)
	var h hub
	deck := startEnv(t, &h, "deck", func(c *Config) {
		c.KeyboardBus = func() (*dbus.Conn, error) { return dbus.Connect(f.Addr) }
	}, "DBUS_SYSTEM_BUS_ADDRESS="+f.Addr)
	m, err := deck.do(t, control.Header{Op: control.OpKeyboard, Name: "on", Keyboard: &control.Keyboard{Layout: "us"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if k := m.Status.Keyboard; k == nil || !k.On || k.Layout != "us" {
		t.Fatalf("after on: %+v", k)
	}
}

// The quick action keyboard-layout moves the keyboard to the next layout,
// and refuses while the keyboard is off.
func TestNextKeyboardLayout(t *testing.T) {
	dir := t.TempDir()
	s := &peripheral.Host{Dir: dir, OS: group.OSLinux, Logf: t.Logf}
	var r *peripheral.Refusal
	if err := s.NextKeyboardLayout(); !errors.As(err, &r) {
		t.Fatalf("with the keyboard off: %v", err)
	}
	if err := blekeyboard.Save(dir, blekeyboard.Settings{On: true, Layout: keyboard.US}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []keyboard.Layout{keyboard.RU, keyboard.US} {
		if err := s.NextKeyboardLayout(); err != nil {
			t.Fatal(err)
		}
		if set, _ := blekeyboard.Load(dir); set.Layout != want || !set.On {
			t.Errorf("after the action: %+v, want the layout %s", set, want)
		}
	}
}
