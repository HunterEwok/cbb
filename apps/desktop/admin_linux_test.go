// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// pkexec gets each argument as it is, with CBB_DEBUG through env.
func TestPkexecArgs(t *testing.T) {
	got := pkexecArgs("/usr/local/bin/cbb", []string{"rename", "ab12", "Bob's $(x)"}, true)
	want := []string{"/usr/bin/env", "CBB_DEBUG=1", "/usr/local/bin/cbb", "rename", "ab12", "Bob's $(x)"}
	if !slices.Equal(got, want) {
		t.Errorf("pkexecArgs = %q, want %q", got, want)
	}
	if got := pkexecArgs("/usr/local/bin/cbb", []string{"remove", "x"}, false); got[0] != "/usr/local/bin/cbb" {
		t.Errorf("without details: %q", got)
	}
}

// pkexec runs cbb only from a place that root owns and no one else may change.
func TestRootOnly(t *testing.T) {
	if !rootOnly("/bin/sh") && !rootOnly("/usr/bin/env") {
		t.Error("neither /bin/sh nor /usr/bin/env counts as root's")
	}
	mine := filepath.Join(t.TempDir(), "cbb")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && rootOnly(mine) {
		t.Error("a file of the user's own counts as root's")
	}
	if rootOnly("/tmp") || rootOnly("/nonexistent/cbb") {
		t.Error("a directory or a missing file counts")
	}
}

// Without a cbb that root owns in its places, nothing is run as root: the
// tray says what to do instead.
func TestRunAdminWithoutRootsCbb(t *testing.T) {
	// A folder anyone may change, so the file counts as no one's but the
	// user's even when the test runs as root.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(dir, "cbb")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	saved := cbbPlaces
	t.Cleanup(func() { cbbPlaces = saved })
	cbbPlaces = []string{mine, "/nonexistent/cbb"}
	if p := cbbPath(); p != "" {
		t.Fatalf("cbbPath = %q, want none", p)
	}
	err := runAdmin([]string{"remove", "ab12"}, "", false)
	var ae *adminError
	if !errors.As(err, &ae) || !strings.Contains(ae.detail, "sudo cbb remove ab12") || !strings.Contains(ae.detail, mine) {
		t.Fatalf("runAdmin = %#v", err)
	}
	cbbPlaces = []string{"/nonexistent/cbb", "/bin/sh"}
	if !rootOnly("/bin/sh") {
		return
	}
	if p := cbbPath(); p != "/bin/sh" {
		t.Errorf("cbbPath = %q, want the place root owns", p)
	}
}

// TestRunAsUser: cbb run as the user; its exit codes say a cancelled
// prompt and an action only the administrator may take, and its last line
// is the error.
func TestRunAsUser(t *testing.T) {
	fake := func(script string) string {
		p := filepath.Join(t.TempDir(), "cbb")
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := runAsUser(fake(`[ "$1 $2 $CBB_DEBUG" = "remove ab12 1" ] && read l && [ "$l" = yes ]`), []string{"remove", "ab12"}, "yes\n", true); err != nil {
		t.Fatalf("a run that succeeds: %v", err)
	}
	if err := runAsUser(fake("exit 75"), nil, "", false); !errors.Is(err, errCancelled) {
		t.Fatalf("a cancelled prompt: %v", err)
	}
	if err := runAsUser(fake("exit 77"), nil, "", false); !errors.Is(err, errNeedsAdmin) {
		t.Fatalf("an action for the administrator: %v", err)
	}
	var ae *adminError
	if err := runAsUser(fake(`echo "cbb: no device \"x\" in the group" >&2; exit 1`), nil, "", false); !errors.As(err, &ae) || ae.msg != `no device "x" in the group` {
		t.Fatalf("a failure: %v", err)
	}
	if err := runAsUser("", nil, "", false); !errors.Is(err, errNeedsAdmin) {
		t.Fatalf("no cbb: %v", err)
	}
	if !needsRoot([]string{"update"}) || !needsRoot([]string{"pair", "-app", "f"}) || needsRoot([]string{"pair", "-qr"}) || needsRoot(nil) {
		t.Fatal("needsRoot")
	}
}
