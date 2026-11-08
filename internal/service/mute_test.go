// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestMute mutes a device for the whole group from the root, and pauses
// receiving on another.
func TestMute(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c := startService(t, &h, "gamma")
	pairWith(t, a, b) // alpha is the root
	pairWith(t, a, c)
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" connected to both others", func() bool { return len(s.status(t).Peers) == 2 })
	}

	// A member that is no admin mutes nobody else for the group.
	if _, err := b.do(t, control.Header{Op: control.OpMute, Device: "gamma"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Fatalf("a member muted another for the group: %v", err)
	}
	// The root mutes beta for an hour: beta's copies stay its own, and a
	// deliberate one is refused.
	if _, err := a.do(t, control.Header{Op: control.OpMute, Device: "beta", ForMS: time.Hour.Milliseconds()}, ""); err != nil {
		t.Fatal(err)
	}
	st := b.status(t)
	if !st.Muted || st.MutedUntilMS < time.Now().Add(59*time.Minute).UnixMilli() {
		t.Fatalf("beta's status after the mute: muted %v until %d", st.Muted, st.MutedUntilMS)
	}
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "noise"); err == nil || !strings.Contains(err.Error(), "muted") {
		t.Fatalf("a muted device sent a copy: %v", err)
	}
	// Its hello says so once it connected again, to both others.
	betaMuted := func(s *testService, muted bool) bool {
		for _, d := range s.devices(t) {
			if d.Name == "beta" {
				return d.Muted == muted && (!muted || d.MutedUntilMS > time.Now().UnixMilli())
			}
		}
		return false
	}
	waitFor(t, "alpha and gamma list beta as muted", func() bool { return betaMuted(a, true) && betaMuted(c, true) })
	// Copies from the others still reach beta.
	waitFor(t, "connected again", func() bool { return len(b.status(t).Peers) == 2 && len(a.status(t).Peers) == 2 })
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from alpha"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta has alpha's text", func() bool { return b.paste(t) == "from alpha" })

	// The mute lasts across a restart, and only an admin ends it.
	b.stop()
	b = restartService(t, &h, b)
	if !b.status(t).Muted {
		t.Fatal("the mute did not last across a restart")
	}
	if _, err := b.do(t, control.Header{Op: control.OpUnmute, Device: "beta"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Fatalf("the muted device's user ended an admin's mute: %v", err)
	}
	waitFor(t, "beta connected to both others", func() bool { return len(b.status(t).Peers) == 2 })
	if _, err := a.do(t, control.Header{Op: control.OpUnmute, Device: "beta"}, ""); err != nil {
		t.Fatal(err)
	}
	if b.status(t).Muted {
		t.Fatal("beta is still muted after the admin's unmute")
	}
	// beta connects again after the unmute, so that its hello shows it.
	waitFor(t, "alpha and gamma list beta as unmuted", func() bool { return betaMuted(a, false) && betaMuted(c, false) })
	// Without a connection a member lists beta as unmuted too, so the
	// links themselves are waited for: beta's to both others by device ID.
	waitFor(t, "beta connected again", func() bool {
		return linked(t, b, a) && linked(t, b, c) && linked(t, a, b) && linked(t, c, b)
	})
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "from beta"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "gamma has beta's text", func() bool { return c.paste(t) == "from beta" })

	// gamma turns sync off for an hour: the group's copies stay out of
	// its clipboard and its own stay home.
	if _, err := c.do(t, control.Header{Op: control.OpSync, Name: "off", ForMS: time.Hour.Milliseconds()}, ""); err != nil {
		t.Fatal(err)
	}
	if st := c.status(t); st.Mode != "own" || st.SyncUntilMS == 0 || st.Muted {
		t.Fatalf("gamma's status with sync off: mode %q until %d, muted %v", st.Mode, st.SyncUntilMS, st.Muted)
	}
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "beta again"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has beta's text", func() bool { return a.paste(t) == "beta again" })
	if _, err := c.do(t, control.Header{Op: control.OpSync, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "beta heard"); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 10*time.Second, "gamma has beta's text again", func() bool { return c.paste(t) == "beta heard" },
		func() string { return links(t, a, b, c) })

	// cbb mute names a device; this device's own sync is cbb sync.
	if _, err := a.do(t, control.Header{Op: control.OpMute, ForMS: time.Hour.Milliseconds()}, ""); err == nil || !strings.Contains(err.Error(), "cbb sync off") {
		t.Errorf("a mute without a device: %v", err)
	}
	// A mute longer than 30 days is refused.
	if _, err := a.do(t, control.Header{Op: control.OpMute, Device: "beta", ForMS: 31 * 24 * time.Hour.Milliseconds()}, ""); err == nil {
		t.Error("a mute of 31 days was taken")
	}
}

// linked reports whether s has a connection to other, with its hello.
func linked(t *testing.T, s, other *testService) bool {
	t.Helper()
	id := other.status(t).Device
	return slices.ContainsFunc(s.status(t).Peers, func(p control.Device) bool { return p.ID == id })
}

// links describes each member's connections and current text, for a
// failure's message.
func links(t *testing.T, all ...*testService) string {
	t.Helper()
	names := map[string]string{}
	for _, s := range all {
		names[s.status(t).Device] = s.name
	}
	var out []string
	for _, s := range all {
		st := s.status(t)
		var peers []string
		for _, p := range st.Peers {
			peers = append(peers, names[p.ID])
		}
		out = append(out, fmt.Sprintf("%s: peers %v, mode %s, text %q", s.name, peers, st.Mode, s.paste(t)))
	}
	return strings.Join(out, "; ")
}
