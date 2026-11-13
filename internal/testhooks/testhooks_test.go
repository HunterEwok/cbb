// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package testhooks

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// ungated are the CBB_TEST_ variables the Go programs read outside the
// hooks: where they dial or fetch, names, the bench's clock (behind
// benchtime itself) and the test stands' own switches.
var ungated = []string{
	"CBB_TEST_STATUS_URL", "CBB_TEST_APPLETV_NAME", "CBB_TEST_RUST_RELAY",
	"CBB_TEST_SCALE", "CBB_TEST_CLOCK", "CBB_TEST_CLOCK_FILE", "CBB_TEST_XHTTP_CA",
}

// Every CBB_TEST_ variable the programs' Go code reads (tests and test
// stands aside) is a hook read here or listed as ungated, and the hooks
// are read nowhere else.
func TestEveryTestVariableIsListed(t *testing.T) {
	root := filepath.Join("..", "..")
	read := regexp.MustCompile(`os\.(?:Getenv|LookupEnv)\("(CBB_TEST_[A-Z0-9_]+)"\)`)
	seen := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") ||
				strings.Contains(p, "testhooks") || strings.Contains(p, "test"+string(filepath.Separator)) {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range read.FindAllStringSubmatch(string(data), -1) {
				seen++
				if slices.Contains(Vars, m[1]) {
					t.Errorf("%s reads the test hook %s itself", p, m[1])
				} else if !slices.Contains(ungated, m[1]) {
					t.Errorf("%s reads %s, neither a test hook nor listed as ungated", p, m[1])
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if seen == 0 {
		t.Fatal("found no variable at all")
	}
}

func TestGetenv(t *testing.T) {
	t.Setenv("CBB_TEST_BLUEZ", "unix:path=/x")
	// A test binary reads the hooks, whatever the build.
	if Getenv("CBB_TEST_BLUEZ") != "unix:path=/x" {
		t.Error("the test did not read its hook")
	}
	if (Note() == "") == Enabled {
		t.Errorf("Note %q in a build with Enabled %v", Note(), Enabled)
	}
	defer func() {
		if recover() == nil {
			t.Error("Getenv took a name that is no hook")
		}
	}()
	Getenv("CBB_PORT")
}

// TestOpen holds the gate's four cases: only a build without the hooks,
// outside go test, reads none of them.
func TestOpen(t *testing.T) {
	for _, c := range []struct{ enabled, underTest, want bool }{
		{false, false, false},
		{false, true, true},
		{true, false, true},
		{true, true, true},
	} {
		if got := open(c.enabled, c.underTest); got != c.want {
			t.Errorf("open(%v, %v) = %v, want %v", c.enabled, c.underTest, got, c.want)
		}
	}
}
