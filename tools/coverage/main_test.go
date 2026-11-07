// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGoProfilesMerge(t *testing.T) {
	// The same block from two test binaries, and from a run on another
	// system: covered once any of them covered it, counted once.
	a := write(t, "a.out", `mode: atomic
github.com/HunterEwok/cbb/internal/group/a.go:1.1,2.2 3 0
github.com/HunterEwok/cbb/internal/group/a.go:3.1,4.2 1 0
github.com/HunterEwok/cbb/internal/group/a.go:3.1,4.2 1 5
github.com/HunterEwok/cbb/internal/desktop/x.go:1.1,2.2 4 0
github.com/HunterEwok/cbb/internal/third_party/cpace/c.go:1.1,2.2 9 0
github.com/HunterEwok/cbb/internal/ei/eitest/s.go:1.1,2.2 9 0
github.com/HunterEwok/cbb/internal/attest/attesttest/s.go:1.1,2.2 9 0
github.com/HunterEwok/cbb/internal/attest/a.go:1.1,2.2 2 0
github.com/HunterEwok/cbb/tools/bench/b.go:1.1,2.2 9 0
`)
	b := write(t, "b.out", `mode: set
github.com/HunterEwok/cbb/internal/desktop/x.go:1.1,2.2 4 1
`)
	var out strings.Builder
	if err := run([]string{a, b}, nil, nil, "", 1, "", &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| go | 5 | 10 | 50.0 |", "| internal/attest | 2 | 0.0 |", "| go-core | 1 | 4 | 25.0 |", "| internal/desktop | 4 | 100.0 |"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "third_party") || strings.Contains(out.String(), "eitest") || strings.Contains(out.String(), "attesttest") || strings.Contains(out.String(), "tools/bench") {
		t.Errorf("copied code, a test fake or a tool counted:\n%s", out.String())
	}
}

func TestFloor(t *testing.T) {
	prof := write(t, "c.out", "mode: set\ngithub.com/HunterEwok/cbb/cmd/cbb/m.go:1.1,2.2 1 1\ngithub.com/HunterEwok/cbb/cmd/cbb/m.go:3.1,4.2 1 0\n")
	for _, c := range []struct {
		floor string
		fail  bool
		say   string
	}{
		{`{"go": 50}`, false, "| ok |"},
		{`{"go": 50.9}`, false, "| ok |"},
		{`{"go": 51.5}`, true, "below the floor"},
		{`{"go": 40}`, false, "raise the floor to 50.0"},
		{`{"go": 50, "rust-core": 90}`, false, "| rust-core | | | not measured |"},
	} {
		floor := write(t, "floor.json", c.floor)
		var out strings.Builder
		err := run([]string{prof}, nil, nil, floor, 1, "", &out)
		if (err != nil) != c.fail {
			t.Errorf("floor %s: error %v, want failure %v", c.floor, err, c.fail)
		}
		if !strings.Contains(out.String(), c.say) {
			t.Errorf("floor %s: no %q in\n%s", c.floor, c.say, out.String())
		}
	}
}

func TestLLVMAndJaCoCo(t *testing.T) {
	llvm := write(t, "rust.json", `{"data":[{"files":[
{"filename":"/w/core/src/certs.rs","summary":{"lines":{"count":10,"covered":9}}},
{"filename":"/w/core/src/third_party/cpace.rs","summary":{"lines":{"count":10,"covered":0}}},
{"filename":"/w/member/src/main.rs","summary":{"lines":{"count":4,"covered":1}}}]}]}`)
	jacoco := write(t, "kit.xml", `<?xml version="1.0"?><!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
<report name="kit"><package name="p"><sourcefile name="A.kt"><counter type="LINE" missed="1" covered="1"/></sourcefile>
<counter type="LINE" missed="1" covered="1"/></package><counter type="INSTRUCTION" missed="5" covered="5"/><counter type="LINE" missed="3" covered="7"/></report>`)
	var out strings.Builder
	err := run(nil, []string{"rust-core=" + llvm, "rust-lite=" + llvm}, []string{"kotlin-kit=" + jacoco}, "", 1, "", &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| rust-core | 9 | 10 | 90.0 |", "| rust-lite | 1 | 4 | 25.0 |", "| kotlin-kit | 7 | 10 | 70.0 |"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in\n%s", want, out.String())
		}
	}
	if err := run(nil, []string{"swift=" + llvm}, nil, "", 1, "", &out); err == nil {
		t.Error("an unknown part taken")
	}
	if err := run(nil, []string{"swift-kit=" + llvm}, nil, "", 1, "", &out); err == nil {
		t.Error("an export with no file of the part taken")
	}
}
