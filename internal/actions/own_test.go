// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package actions

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The session runs a command only when its user set that very command
// for the action, in the file cbb action add writes.
func TestOwnCommandOnlyAsItsUserSet(t *testing.T) {
	dir := t.TempDir()
	var r *Refusal
	if err := OwnCommandAllowed(dir, "backup", []string{"/usr/bin/true"}); !errors.As(err, &r) {
		t.Fatalf("no file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, OwnFile), []byte(`{"backup":["/usr/bin/true","-x"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := OwnCommandAllowed(dir, "backup", []string{"/usr/bin/true", "-x"}); err != nil {
		t.Fatalf("the user's command: %v", err)
	}
	for _, c := range []struct {
		name    string
		command []string
	}{
		{"backup", []string{"/bin/sh", "-c", "x"}},
		{"backup", []string{"/usr/bin/true"}},
		{"backup", []string{"/usr/bin/true", "-x", "-y"}},
		{"other", []string{"/usr/bin/true", "-x"}},
	} {
		if err := OwnCommandAllowed(dir, c.name, c.command); !errors.As(err, &r) {
			t.Errorf("%s %q: %v", c.name, c.command, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, OwnFile), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := OwnCommandAllowed(dir, "backup", []string{"/usr/bin/true", "-x"}); !errors.As(err, &r) {
		t.Fatalf("a broken file: %v", err)
	}
}
