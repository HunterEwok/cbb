// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
	misuse("recovery", "now")

	want("This device is the remote of no TV", "remote")
	misuse("remote", "-tv", "x", "add", "10.0.0.5")
	misuse("keyboard", "off", "-rate", "20")

	deck := startService(t, &h, "deck")
	misuse("pair", "-now")
	pair := exec.Command(bin, "-state", pi.dir, "-socket", pi.socket, "pair")
	stdout, err := pair.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pair.Process.Kill(); pair.Wait() })
	lines := bufio.NewScanner(stdout)
	var code string
	for code == "" && lines.Scan() {
		if c, ok := strings.CutPrefix(lines.Text(), "Pairing code: "); ok {
			code = strings.ReplaceAll(c, " ", "")
		}
	}
	if len(code) != 6 {
		t.Fatalf("cbb pair showed no code: %v", lines.Err())
	}
	if _, err := deck.do(t, control.Header{Op: control.OpJoin, Code: code}, ""); err != nil {
		t.Fatalf("join on deck: %v", err)
	}
	var rest strings.Builder
	for lines.Scan() {
		rest.WriteString(lines.Text() + "\n")
	}
	if err := pair.Wait(); err != nil || !strings.Contains(rest.String(), "deck joined the group.") {
		t.Fatalf("cbb pair ended with %v: %s", err, rest.String())
	}
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
	// Files go to the group with cbb copy and come out with cbb paste -o.
	files := t.TempDir()
	report := filepath.Join(files, "report.txt")
	if err := os.WriteFile(report, []byte("the quarter's numbers"), 0o644); err != nil {
		t.Fatal(err)
	}
	want("Copied report.txt (21 bytes) to the group.", "copy", report)
	misuse("copy", "-secret", report)
	out := t.TempDir()
	waitFor(t, "desk saves the file", func() bool {
		got, err := exec.Command(bin, "-state", deck.dir, "-socket", deck.socket, "paste", "-o", out).CombinedOutput()
		return err == nil && strings.TrimSpace(string(got)) == filepath.Join(out, "report.txt")
	})
	if b, err := os.ReadFile(filepath.Join(out, "report.txt")); err != nil || string(b) != "the quarter's numbers" {
		t.Fatalf("the saved file: %q, %v", b, err)
	}
	want("Sync is off on desk now.", "sync", "-on", "desk", "off")
	waitFor(t, "desk's sync is off", func() bool { return deck.status(t).Mode == "own" })
	want("Sync is on on desk now.", "sync", "-on", "desk", "on")
	misuse("sync", "-on", "desk", "off", "-for", "1h")
	want("Remote paste is off on desk.", "paste-receive", "off", "-on", "desk")
	want("The quick actions are off on desk.", "action", "off", "-on", "desk")
	want("Sync is off until cbb sync on", "sync", "off")
	want("Sync is on: copies here go to the group", "sync", "on")
	want("Removed desk from the group", "remove", "desk")
	misuse("remove")
}
