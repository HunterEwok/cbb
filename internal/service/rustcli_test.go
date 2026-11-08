// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestRustCommandLine runs the Rust cbb's group commands against Rust
// services: each says what the Go cbb says, changes what it names, and a
// wrong use exits with 2. CBB_TEST_RUST_SERVICE names the binary.
func TestRustCommandLine(t *testing.T) {
	bin := rustService()
	if bin == "" {
		t.Skip("CBB_TEST_RUST_SERVICE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	run := func(args ...string) (string, int) {
		t.Helper()
		out, err := exec.Command(bin, append([]string{"-state", pi.dir, "-socket", pi.socket}, args...)...).CombinedOutput()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return string(out), 0
		case errors.As(err, &exit):
			return string(out), exit.ExitCode()
		}
		t.Fatalf("cbb %s: %v", strings.Join(args, " "), err)
		return "", 0
	}
	want := func(part string, args ...string) {
		t.Helper()
		out, code := run(args...)
		if code != 0 || !strings.Contains(out, part) {
			t.Fatalf("cbb %s exited with %d: %s; want %q", strings.Join(args, " "), code, out, part)
		}
	}
	misuse := func(args ...string) {
		t.Helper()
		if out, code := run(args...); code != 2 || !strings.Contains(out, "usage: ") {
			t.Fatalf("cbb %s exited with %d: %s; want a usage error", strings.Join(args, " "), code, out)
		}
	}

	want("Created the group", "new")
	misuse("new", "now")
	want("A copy from another device goes into the clipboard for", "incoming")
	want("for 30s after it arrives", "incoming", "30s")
	want("for 30s after it arrives", "incoming")
	misuse("incoming", "soon")
	want("Key level ", "keys")
	misuse("keys", "a", "b")
	want("max-copy-away", "config")
	misuse("config", "max-copy")
	want("This network is one where the group is now", "network")
	want("now waits 48h on each member", "takeover", "-delay", "48h")
	misuse("takeover", "-delay")

	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	misuse("rename", "deck")
	want("Renamed deck to desk", "rename", "deck", "desk")
	waitFor(t, "the root lists desk", func() bool {
		return slices.ContainsFunc(pi.devices(t), func(d control.Device) bool { return d.Name == "desk" })
	})
	waitFor(t, "desk is connected to the root", func() bool {
		return slices.ContainsFunc(pi.status(t).Peers, func(p control.Device) bool { return p.ID == deck.status(t).Device })
	})
	want("desk is muted", "mute", "-on", "desk", "-for", "1h")
	want("desk is no longer muted", "unmute", "-on", "desk")
	misuse("mute", "-on", "desk", "-for", "a while")
	want("Removed desk from the group", "remove", "desk")
	misuse("remove")
}
