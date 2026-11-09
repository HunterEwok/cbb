// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommandKeys: cbb relay makes its key on the first run, keeps it, and
// prints the pin users give the hub; it takes only flags, and a damaged key
// file stops it.
func TestCommandKeys(t *testing.T) {
	key := filepath.Join(t.TempDir(), "relay.pem")
	var pins []string
	for range 2 {
		var stdout, stderr bytes.Buffer
		if code := Command([]string{"-key", key, "-show-key"}, &stdout, &stderr, ""); code != 0 {
			t.Fatalf("-show-key: %d, %s", code, stderr.String())
		}
		pins = append(pins, strings.TrimSpace(stdout.String()))
	}
	if pins[0] == "" || pins[0] != pins[1] {
		t.Errorf("the pins of two runs: %q", pins)
	}
	var stdout, stderr bytes.Buffer
	if code := Command([]string{"extra"}, &stdout, &stderr, key); code != 2 || !strings.Contains(stderr.String(), "takes only flags") {
		t.Errorf("an argument: %d, %q", code, stderr.String())
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := Command([]string{"-key", bad, "-show-key"}, &stdout, &stderr, ""); code != 1 || stderr.Len() == 0 {
		t.Errorf("a damaged key: %d, %q", code, stderr.String())
	}
}

func TestPortOf(t *testing.T) {
	for in, want := range map[string]string{"[::]:8765": "8765", "0.0.0.0:443": "443", "8764": "8764"} {
		if got := PortOf(in); got != want {
			t.Errorf("PortOf(%q) = %q, want %q", in, got, want)
		}
	}
}
