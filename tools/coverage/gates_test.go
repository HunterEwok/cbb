// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeIn(t *testing.T, dir, name, text string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuditGate(t *testing.T) {
	root := t.TempDir()
	writeIn(t, root, "a/a_test.go", "package a\n\nfunc TestHeld(t *testing.T) {}\n")
	writeIn(t, root, "b/lib.rs", "#[test]\nfn held() {}\n")
	writeIn(t, root, "c/T.swift", "    func testHeld() throws {}\n")
	writeIn(t, root, "d/T.kt", "    fun held() {}\n    fun `held too`() {}\n")
	list := writeIn(t, root, "closed.json", `[
 {"id": "x-1", "tests": [{"lang": "go", "file": "a/a_test.go", "name": "TestHeld"},
                         {"lang": "rust", "file": "b/lib.rs", "name": "held"}]},
 {"id": "x-2", "tests": [{"lang": "swift", "file": "c/T.swift", "name": "testHeld"},
                         {"lang": "kotlin", "file": "d/T.kt", "name": "held"},
                         {"lang": "kotlin", "file": "d/T.kt", "name": "held too"}]}
]`)
	g, err := auditGate(list, root)
	if err != nil || g.failed() || g.met != 2 || g.of != 2 {
		t.Fatalf("held: %+v, %v", g, err)
	}

	// A test renamed away, a file gone, a finding with no test.
	list = writeIn(t, root, "closed.json", `[
 {"id": "x-1", "tests": [{"lang": "go", "file": "a/a_test.go", "name": "TestHel"}]},
 {"id": "x-2", "tests": [{"lang": "rust", "file": "gone.rs", "name": "held"}]},
 {"id": "x-3", "tests": []},
 {"id": "x-4", "tests": [{"lang": "rust", "file": "b/lib.rs", "name": "held"}]}
]`)
	g, err = auditGate(list, root)
	if err != nil || !g.failed() || g.met != 1 || g.of != 4 || len(g.missing) != 2 {
		t.Fatalf("gone: %+v, %v", g, err)
	}

	for name, text := range map[string]string{
		"repeated id":   `[{"id": "x", "tests": []}, {"id": "x", "tests": []}]`,
		"empty id":      `[{"id": "", "tests": []}]`,
		"unknown lang":  `[{"id": "x", "tests": [{"lang": "c", "file": "a", "name": "b"}]}]`,
		"unknown field": `[{"id": "x", "title": "no titles here", "tests": []}]`,
		"not json":      `{`,
	} {
		if _, err := auditGate(writeIn(t, root, "bad.json", text), root); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if _, err := auditGate(filepath.Join(root, "none.json"), root); err == nil {
		t.Error("no list: taken")
	}
}

// The list in the tree names tests that exist.
func TestClosedFindings(t *testing.T) {
	g, err := auditGate("../../testdata/audit/closed.json", "../..")
	if err != nil {
		t.Fatal(err)
	}
	if g.failed() || g.of == 0 {
		t.Fatalf("%d of %d findings hold: %s", g.met, g.of, strings.Join(g.missing, "; "))
	}
}

func TestFormatGate(t *testing.T) {
	dir := t.TempDir()
	src, vectors := filepath.Join(dir, "src"), filepath.Join(dir, "vectors")
	writeIn(t, dir, "src/plain.rs", "fn f() {}\n")
	writeIn(t, dir, "vectors/a.json", `{}`)
	g, err := formatGate(src, vectors)
	if err != nil || g.note == "" || g.failed() {
		t.Fatalf("before the readers: %+v, %v", g, err)
	}

	writeIn(t, dir, "src/format/grant.rs", `Err(Rule::field("grants/life")); Err(Rule::field("grants/replaces")); Rule::field("copy/commit")`)
	writeIn(t, dir, "src/notes.txt", `Rule::field("not/rust")`)
	g, err = formatGate(src, filepath.Join(dir, "empty"))
	if err != nil || g.note == "" {
		t.Fatalf("no vectors: %+v, %v", g, err)
	}

	writeIn(t, dir, "vectors/a.json", `{"refuse": [{"name": "n", "rule": "grants/life", "verdict": "refuse"},
		{"name": "kept", "rule": "grants/replaces", "verdict": "hold"}],
		"refuse_copies": [{"name": "c", "rule": "copy/commit"}]}`)
	g, err = formatGate(src, vectors)
	if err != nil || !g.failed() || g.met != 2 || g.of != 3 || strings.Join(g.missing, ",") != "grants/replaces" {
		t.Fatalf("one rule without a refusal: %+v, %v", g, err)
	}

	writeIn(t, dir, "vectors/b.json", `[{"rule": "grants/replaces", "verdict": "refuse"}]`)
	g, err = formatGate(src, vectors)
	if err != nil || g.failed() || g.met != 3 {
		t.Fatalf("all refused: %+v, %v", g, err)
	}

	writeIn(t, dir, "vectors/c.json", `{`)
	if _, err := formatGate(src, vectors); err == nil {
		t.Error("bad vectors: taken")
	}
	if _, err := formatGate(filepath.Join(dir, "none"), vectors); err == nil {
		t.Error("no sources: taken")
	}
}

func TestMutantsGate(t *testing.T) {
	dir := t.TempDir()
	known := writeIn(t, dir, "known.txt", "# why\na.rs: replace + with -\n\na.rs: replace < with <=\na.rs: replace < with <=\n")
	missed := writeIn(t, dir, "missed.txt", "a.rs:10:5: replace + with -\na.rs:20:1: replace < with <=\na.rs:21:1: replace < with <=\n")
	g, err := mutantsGate(missed, known)
	if err != nil || g.failed() || g.met != 3 || g.of != 3 {
		t.Fatalf("known: %+v, %v", g, err)
	}
	missed = writeIn(t, dir, "missed.txt", "a.rs:10:5: replace + with -\na.rs:1:1: replace + with -\nb.rs:2:2: replace == with !=\n")
	g, err = mutantsGate(missed, known)
	if err != nil || !g.failed() || g.met != 1 || len(g.missing) != 2 {
		t.Fatalf("new: %+v, %v", g, err)
	}
	if _, err := mutantsGate(filepath.Join(dir, "none"), known); err == nil {
		t.Error("no run: taken")
	}
	if _, err := mutantsGate(missed, filepath.Join(dir, "none")); err == nil {
		t.Error("no list: taken")
	}
}

func TestGatesInTheTable(t *testing.T) {
	dir := t.TempDir()
	writeIn(t, dir, "a_test.go", "func TestA(t *testing.T) {}\n")
	audit := writeIn(t, dir, "closed.json", `[{"id": "x-1", "tests": [{"lang": "go", "file": "a_test.go", "name": "TestA"}]}]`)
	writeIn(t, dir, "src/a.rs", "")
	known := writeIn(t, dir, "known.txt", "")
	missed := writeIn(t, dir, "missed.txt", "")
	o := options{audit: audit, root: dir, rules: filepath.Join(dir, "src"), vectors: dir, mutants: missed, knownMutants: known}
	var out strings.Builder
	if err := run(o, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Hard gates", "| closed audit findings with a test | 1 | 1 | ok |", "not measured: no reader", "| surviving mutants the known list names | 0 | 0 | ok |"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in\n%s", want, out.String())
		}
	}

	writeIn(t, dir, "missed.txt", "a.rs:1:1: replace + with -\n")
	out.Reset()
	err := run(o, &out)
	if err == nil || !strings.Contains(err.Error(), "surviving mutants") || !strings.Contains(out.String(), "failed: a.rs: replace + with -") {
		t.Fatalf("a new survivor: %v\n%s", err, out.String())
	}

	if err := run(options{rules: dir}, &out); err == nil {
		t.Error("-rules without -vectors: taken")
	}
	for _, o := range []options{{audit: filepath.Join(dir, "none")}, {rules: filepath.Join(dir, "none"), vectors: dir}, {mutants: filepath.Join(dir, "none")}} {
		if err := run(o, &out); err == nil {
			t.Errorf("%+v: taken", o)
		}
	}
}
