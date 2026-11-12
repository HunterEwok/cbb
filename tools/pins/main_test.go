// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"11.1.3", "10.2.4", true},
		{"10.2.4", "11.1.3", false},
		{"0.15.2", "0.15.2", false},
		{"1.10", "1.9.9", true},
		{"2.3.1", "2.3", true},
		{"2.3", "2.3.0", false},
		{"esp-develop-9.2.2-20260601", "esp-develop-9.2.2-20260417", true},
		{"esp-develop-9.2.2-20260417", "esp-develop-9.2.2-20260417", false},
	} {
		if got := newer(c.a, c.b); got != c.want {
			t.Errorf("newer(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestChoose(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC) }
	rels := []release{{"0.15.2", day(1)}, {"0.16.0", day(3)}, {"0.17.1", day(10)}, {"0.9.0", day(2)}}
	due, newest := choose(rels, day(7))
	if due.version != "0.16.0" || newest.version != "0.17.1" {
		t.Fatalf("choose = %s, %s; want 0.16.0, 0.17.1", due.version, newest.version)
	}
	if due, _ := choose(rels[2:3], day(7)); due.version != "" {
		t.Fatalf("a release within the cooldown was due: %s", due.version)
	}
}

// TestPinsFound checks that every pattern still finds its pin in the
// repository, so that a renamed variable is noticed in CI, not only in
// the weekly run.
func TestPinsFound(t *testing.T) {
	if err := os.Chdir(filepath.Join("..", "..")); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, g := range files {
		m, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, m...)
	}
	for _, p := range pins {
		f, err := scan(p.re, paths)
		if err != nil {
			t.Fatal(err)
		}
		if len(f) == 0 {
			t.Errorf("%s: no pin found", p.name)
		}
	}
	if f, err := scan(nightlyRe, paths); err != nil || len(f) == 0 {
		t.Errorf("nightly Rust: no pin found (%v)", err)
	}
	for _, c := range commitPins {
		if f, err := scan(c.re, paths); err != nil || len(f) != 1 {
			t.Errorf("%s: pins found %v (%v), want one", c.name, f, err)
		}
	}
}

// TestCommitPin checks that a module's pin is read as its commit's time and
// falls behind by age: gVisor's pin of January 2026 was too old by March.
func TestCommitPin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "go.mod")
	line := "require (\n\tgvisor.dev/gvisor v0.0.0-20260122175437-89a5d21be8f0\n)\n"
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := scan(commitPins[0].re, []string{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f["20260122175437"] == nil {
		t.Fatalf("scan = %v, want 20260122175437", f)
	}
	if ok, age := commitFresh("20260122175437", time.Date(2026, 2, 20, 0, 0, 0, 0, time.UTC), 30); !ok || age != 28 {
		t.Errorf("after 28 days: fresh %v, age %d", ok, age)
	}
	if ok, age := commitFresh("20260122175437", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), 30); ok || age != 37 {
		t.Errorf("after 37 days: fresh %v, age %d", ok, age)
	}
	if ok, _ := commitFresh("2026012217543x", time.Now(), 30); ok {
		t.Error("a malformed time passed")
	}
}

// TestXrayPin checks that the Xray-core pin reads the tag from go.mod's
// comment, not the commit beside it.
func TestXrayPin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "go.mod")
	line := "require (\n\tgithub.com/xtls/xray-core v1.260327.1-0.20261031132019-a4a3dff5b20c // v26.10.31\n)\n"
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := scan(xrayRe, []string{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f["26.10.31"] == nil {
		t.Fatalf("scan = %v, want 26.10.31", f)
	}
}
