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
	if err := run(options{goFiles: []string{a, b}, slack: 1}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| go | lines | 5 | 10 | 50.0 |", "| internal/attest | 2 | 0.0 |", "| go-core | lines | 1 | 4 | 25.0 |", "| internal/desktop | 4 | 100.0 |"} {
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
		{`{"go": 50, "rust-core": 90}`, false, "| rust-core | lines | | | not measured |"},
	} {
		floor := write(t, "floor.json", c.floor)
		var out strings.Builder
		err := run(options{goFiles: []string{prof}, floorFile: floor, slack: 1}, &out)
		if (err != nil) != c.fail {
			t.Errorf("floor %s: error %v, want failure %v", c.floor, err, c.fail)
		}
		if !strings.Contains(out.String(), c.say) {
			t.Errorf("floor %s: no %q in\n%s", c.floor, c.say, out.String())
		}
	}
}

// With a target above the floors, a part between the two is marked and
// warned of, and the run still passes; below the floor it fails as before.
func TestTarget(t *testing.T) {
	prof := write(t, "c.out", "mode: set\ngithub.com/HunterEwok/cbb/cmd/cbb/m.go:1.1,2.2 1 1\ngithub.com/HunterEwok/cbb/cmd/cbb/m.go:3.1,4.2 1 0\n")
	for _, c := range []struct {
		floor  string
		target float64
		fail   bool
		say    []string
	}{
		{`{"go": 45}`, 90, false, []string{"| below the target of 90 |", "::warning title=coverage below the target::go 50.0% < 90%"}},
		{`{"go": 45}`, 50, false, []string{"| ok |"}},
		{`{"go": 60}`, 90, true, []string{"below the floor"}},
	} {
		floor := write(t, "floor.json", c.floor)
		var out strings.Builder
		err := run(options{goFiles: []string{prof}, floorFile: floor, slack: 1, target: c.target}, &out)
		if (err != nil) != c.fail {
			t.Errorf("floor %s, target %v: error %v, want failure %v", c.floor, c.target, err, c.fail)
		}
		for _, say := range c.say {
			if !strings.Contains(out.String(), say) {
				t.Errorf("floor %s, target %v: no %q in\n%s", c.floor, c.target, say, out.String())
			}
		}
		if !c.fail && c.target <= 50 && strings.Contains(out.String(), "::warning") {
			t.Errorf("a warning at the target:\n%s", out.String())
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
	err := run(options{llvmFiles: []string{"rust-core=" + llvm, "rust-member=" + llvm}, jacocoFiles: []string{"kotlin-kit=" + jacoco}, slack: 1}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| rust-core | lines | 9 | 10 | 90.0 |", "| rust-member | lines | 1 | 4 | 25.0 |", "| kotlin-kit | lines | 7 | 10 | 70.0 |"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in\n%s", want, out.String())
		}
	}
	if err := run(options{llvmFiles: []string{"swift=" + llvm}, slack: 1}, &out); err == nil {
		t.Error("an unknown part taken")
	}
	if err := run(options{llvmFiles: []string{"swift-kit=" + llvm}, slack: 1}, &out); err == nil {
		t.Error("an export with no file of the part taken")
	}
}

// TestBranches: the branches of JaCoCo and of an llvm-cov export that
// counted them are rows of their own, with floors and targets of their
// own, a core's branches held to the core's target.
func TestBranches(t *testing.T) {
	llvm := write(t, "rust.json", `{"data":[{"files":[
{"filename":"/w/core/src/certs.rs","summary":{"lines":{"count":10,"covered":9},"branches":{"count":20,"covered":17}}},
{"filename":"/w/member/src/main.rs","summary":{"lines":{"count":4,"covered":4},"branches":{"count":0,"covered":0}}}]}]}`)
	jacoco := write(t, "kit.xml", `<report name="kit"><package name="p"><counter type="BRANCH" missed="9" covered="1"/></package>
<counter type="BRANCH" missed="2" covered="8"/><counter type="LINE" missed="0" covered="10"/></report>`)
	floor := write(t, "floor.json", `{"rust-core/branches": 80, "kotlin-kit/branches": 79}`)
	var out strings.Builder
	o := options{llvmFiles: []string{"rust-core=" + llvm, "rust-member=" + llvm}, jacocoFiles: []string{"kotlin-kit=" + jacoco},
		floorFile: floor, slack: 1, target: 90, branchTarget: 80, coreBranchTarget: 90}
	if err := run(o, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"| rust-core | branches | 17 | 20 | 85.0 | 80.0 | below the target of 90 |",
		"| kotlin-kit | branches | 8 | 10 | 80.0 | 79.0 | ok |",
		"| kotlin-kit | lines | 10 | 10 | 100.0 | - | ok |",
		"::warning title=coverage below the target::rust-core/branches 85.0% < 90%",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "rust-member | branches") {
		t.Errorf("branches of a build that did not count them:\n%s", out.String())
	}
	if o.targetOf("swift-kit/branches") != 80 || o.targetOf("go-core/branches") != 90 || o.targetOf("go") != 90 {
		t.Error("the targets of the rows")
	}
	o.coreBranchTarget = 0
	if o.targetOf("rust-core/branches") != 80 {
		t.Error("a core without its own target")
	}
}
