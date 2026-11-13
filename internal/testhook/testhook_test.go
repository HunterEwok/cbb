// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package testhook

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadInTests(t *testing.T) {
	t.Setenv("CBB_TEST_RESOLVE", "relay.example.org=127.0.0.1")
	if !Enabled() || Getenv("CBB_TEST_RESOLVE") != "relay.example.org=127.0.0.1" {
		t.Fatal("a test binary does not read the hooks")
	}
}

// TestNotReadInAProgram builds a program without the tag testhooks, as a
// release's, and with it, and runs both with a hook set.
func TestNotReadInAProgram(t *testing.T) {
	if testing.Short() {
		t.Skip("builds programs")
	}
	dir := t.TempDir()
	for _, c := range []struct {
		tags, want string
	}{{"", ""}, {"testhooks", "relay.example.org=127.0.0.1"}} {
		bin := filepath.Join(dir, "prog"+c.tags)
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		build := exec.Command("go", "build", "-tags="+c.tags, "-o", bin, "./testdata/prog")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go build -tags=%q: %v\n%s", c.tags, err, out)
		}
		run := exec.Command(bin)
		run.Env = append(os.Environ(), "CBB_TEST_RESOLVE=relay.example.org=127.0.0.1")
		out, err := run.Output()
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(out)); got != c.want {
			t.Errorf("built with -tags=%q: the hook reads %q, want %q", c.tags, got, c.want)
		}
	}
}
