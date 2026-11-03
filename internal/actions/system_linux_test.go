// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package actions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGrant writes the polkit rule for the presets that are on, as a JS
// rule or, with the old polkit, a .pkla file, and removes it when none
// needs a right.
func TestGrant(t *testing.T) {
	old := polkitRoot
	t.Cleanup(func() { polkitRoot = old })

	polkitRoot = t.TempDir()
	if _, err := Grant([]string{Reboot}); err == nil || !strings.Contains(err.Error(), "polkit is not installed") {
		t.Errorf("without polkit: %v", err)
	}
	if _, err := Grant([]string{Restart}); err != nil {
		t.Errorf("restart needs no polkit: %v", err)
	}

	os.MkdirAll(filepath.Join(polkitRoot, "usr/share/polkit-1/rules.d"), 0o755)
	path, err := Grant([]string{Lock, Reboot, Restart})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{`subject.user != "cbb"`, `"org.freedesktop.login1.lock-sessions"`, `"org.freedesktop.login1.reboot-multiple-sessions"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s lacks %s:\n%s", path, want, b)
		}
	}
	if strings.Contains(string(b), "power-off") {
		t.Errorf("the rule grants shutdown, which is off:\n%s", b)
	}
	if _, err := Grant([]string{Restart}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the rule stays with nothing on that needs it: %v", err)
	}

	polkitRoot = t.TempDir()
	os.MkdirAll(filepath.Join(polkitRoot, "etc/polkit-1/localauthority"), 0o755)
	path, err = Grant([]string{Sleep})
	if err != nil || !strings.HasSuffix(path, ".pkla") {
		t.Fatalf("the old polkit: %s, %v", path, err)
	}
	b, _ = os.ReadFile(path)
	if !strings.Contains(string(b), "Identity=unix-user:cbb\nAction=org.freedesktop.login1.suspend;org.freedesktop.login1.suspend-multiple-sessions\n") {
		t.Errorf("the .pkla file:\n%s", b)
	}
}
