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
	for _, m := range modulePins {
		if f, err := scanAny(m.re, paths); err != nil || len(f) != 1 {
			t.Errorf("%s: pins found %v (%v), want one", m.name, f, err)
		}
	}
	if f, err := scan(espRe, paths); err != nil || len(f) != 1 {
		t.Errorf("esp-hal: pins found %v (%v), want one", f, err)
	}
}

// TestModuleLag checks the rule for a module pinned at a commit: behind
// only when a newer version is more than the days newer and out for the
// cooldown. gVisor's pin of January 2026 was behind August's fix.
func TestModuleLag(t *testing.T) {
	day := func(m, d int) time.Time { return time.Date(2026, time.Month(m), d, 0, 0, 0, 0, time.UTC) }
	pinned := modInfo{"v0.0.0-20260122175437-89a5d21be8f0", day(1, 22)}
	for _, c := range []struct {
		latest modInfo
		cutoff time.Time
		behind bool
	}{
		{modInfo{"v0.0.0-20260823000000-1b2946c4fa59", day(8, 23)}, day(11, 5), true},
		{modInfo{"v0.0.0-20260210000000-aaaaaaaaaaaa", day(2, 10)}, day(11, 5), false},  // 19 days newer
		{modInfo{"v0.0.0-20261110000000-bbbbbbbbbbbb", day(11, 10)}, day(11, 5), false}, // in its cooldown
		{pinned, day(11, 5), false},
	} {
		if behind, lag := lagging(pinned, c.latest, c.cutoff, 30); behind != c.behind {
			t.Errorf("latest %s: behind %v (lag %d), want %v", c.latest.Version, behind, lag, c.behind)
		}
	}
	// amneziawg-go: the pin is a commit after its newest tag.
	awg := modInfo{"v0.2.20-0.20260724121833-457d920a1a7d", day(7, 24)}
	if behind, _ := lagging(awg, modInfo{"v0.2.19", day(6, 17)}, day(11, 5), 30); behind {
		t.Error("a pin newer than the newest tag is behind")
	}
	if got := escapeModule("github.com/BurntSushi/toml"); got != "github.com/!burnt!sushi/toml" {
		t.Errorf("escapeModule = %s", got)
	}
}

// TestCopiesPins checks that the copies' READMEs give their versions.
func TestCopiesPins(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "README.md")
	text := "copied from\nv0.2.20-0.20260724121833-457d920a1a7d (module checksum\n" +
		"github.com/gballet/go-libpcsclite at v0.0.0-20250918194357-1ec6f2e601c6. The BSD\n" +
		"[`rsc.io/cmd/mote`](https://pkg.go.dev/rsc.io/cmd/mote) v0.1.3\n"
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []string{"v0.2.20-0.20260724121833-457d920a1a7d", "v0.0.0-20250918194357-1ec6f2e601c6", "v0.1.3"}
	for i, m := range modulePins[1:] {
		f, err := scanAny(m.re, []string{p})
		if err != nil || len(f) != 1 || f[want[i]] == nil {
			t.Errorf("%s: %v (%v), want %s", m.name, f, err, want[i])
		}
	}
}
