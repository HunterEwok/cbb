// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const h1 = "1111111111111111111111111111111111111111111111111111111111111111"
const h2 = "2222222222222222222222222222222222222222222222222222222222222222"

func frozen(breaks int, reason string, hashes map[string]string) *Frozen {
	return &Frozen{State: "frozen", Breaks: breaks, Reason: reason, Hashes: hashes}
}

func TestParseRoundTrip(t *testing.T) {
	f := frozen(1, "the copy's field 4", map[string]string{"a.json": h1, "b.json": h2})
	g, err := Parse(f.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(g.Bytes()) != string(f.Bytes()) {
		t.Fatalf("round trip:\n%s\n%s", f.Bytes(), g.Bytes())
	}
}

func TestParseRefuses(t *testing.T) {
	for name, text := range map[string]string{
		"no state":      "breaks: 0\nbreak: -\n",
		"bad state":     "state: thawed\nbreaks: 0\nbreak: -\n",
		"too many":      "state: frozen\nbreaks: 2\nbreak: x\n",
		"draft breaks":  "state: draft\nbreaks: 1\nbreak: x\n",
		"twice":         "state: draft\nstate: draft\nbreaks: 0\nbreak: -\n",
		"bad hash":      "state: draft\nbreaks: 0\nbreak: -\nsha256 abc a.json\n",
		"path":          "state: draft\nbreaks: 0\nbreak: -\nsha256 " + h1 + " ../a.json\n",
		"file twice":    "state: draft\nbreaks: 0\nbreak: -\nsha256 " + h1 + " a.json\nsha256 " + h2 + " a.json\n",
		"unknown key":   "state: draft\nbreaks: 0\nbreak: -\nmax: 9\n",
		"negative":      "state: draft\nbreaks: -1\nbreak: -\n",
		"empty reason":  "state: draft\nbreaks: 0\nbreak:\n",
		"not a vector":  "state: draft\nbreaks: 0\nbreak: -\nsha256 " + h1 + " gen.py\n",
		"short hash ln": "state: draft\nbreaks: 0\nbreak: -\nsha256 " + h1 + "\n",
	} {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestStep(t *testing.T) {
	draft := &Frozen{State: "draft", Reason: "-", Hashes: map[string]string{"a.json": h1}}
	f0 := frozen(0, "-", map[string]string{"a.json": h1})
	for _, c := range []struct {
		name          string
		parent, child *Frozen
		ok            bool
	}{
		{"first", nil, draft, true},
		{"first frozen", nil, f0, true},
		{"first with a break", nil, frozen(1, "x", nil), false},
		{"draft changes freely", draft, &Frozen{State: "draft", Reason: "-", Hashes: map[string]string{"a.json": h2}}, true},
		{"the freeze", draft, f0, true},
		{"back to draft", f0, draft, false},
		{"unchanged", f0, f0, true},
		{"a new vector", f0, frozen(0, "-", map[string]string{"a.json": h1, "b.json": h2}), true},
		{"changed without a break", f0, frozen(0, "-", map[string]string{"a.json": h2}), false},
		{"dropped without a break", f0, frozen(0, "-", map[string]string{}), false},
		{"the one break", f0, frozen(1, "why", map[string]string{"a.json": h2}), true},
		{"a break without a reason", f0, frozen(1, "-", map[string]string{"a.json": h2}), false},
		{"two breaks at once", f0, frozen(2, "why", map[string]string{"a.json": h2}), false},
		{"a break counted for nothing", f0, frozen(1, "why", map[string]string{"a.json": h1}), false},
		{"the same reason again", frozen(1, "why", map[string]string{"a.json": h2}), frozen(2, "why", map[string]string{"a.json": h1}), false},
	} {
		err := Step(c.parent, c.child)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestWrite(t *testing.T) {
	files := map[string]string{"a.json": h1}
	d, err := Write(nil, files, "", false)
	if err != nil || d.State != "draft" {
		t.Fatal(d, err)
	}
	if _, err := Write(d, files, "why", false); err == nil {
		t.Error("a break before the freeze")
	}
	f, err := Write(d, files, "", true)
	if err != nil || f.State != "frozen" || f.Breaks != 0 {
		t.Fatal(f, err)
	}
	moved := map[string]string{"a.json": h2}
	if _, err := Write(f, moved, "", false); err == nil {
		t.Error("a frozen vector changed without -break")
	}
	if _, err := Write(f, files, "why", false); err == nil {
		t.Error("-break with nothing changed")
	}
	if _, err := Write(f, moved, "two\nlines", false); err == nil {
		t.Error("a reason of two lines")
	}
	b, err := Write(f, moved, "why", false)
	if err != nil || b.Breaks != 1 || b.Reason != "why" {
		t.Fatal(b, err)
	}
	if err := Step(f, b); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(b, files, "again", false); err == nil {
		t.Error("a second break before 1.0")
	}
	added, err := Write(b, map[string]string{"a.json": h2, "b.json": h1}, "", false)
	if err != nil || added.Breaks != 1 {
		t.Fatal("adding a vector is not a break:", err)
	}
}

func TestCheck(t *testing.T) {
	f := frozen(0, "-", map[string]string{"a.json": h1})
	if err := Check(f, map[string]string{"a.json": h1}); err != nil {
		t.Fatal(err)
	}
	for name, files := range map[string]map[string]string{
		"changed":  {"a.json": h2},
		"missing":  {},
		"unlisted": {"a.json": h1, "b.json": h2},
	} {
		if err := Check(f, files); err == nil {
			t.Errorf("%s: passed", name)
		}
	}
}

// TestRepository checks the manifest in the repository against its vectors.
func TestRepository(t *testing.T) {
	root := filepath.Join("..", "..")
	b, err := os.ReadFile(filepath.Join(root, Dir, Manifest))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Hashes(filepath.Join(root, Dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(f, files); err != nil {
		t.Fatal(err)
	}
}

// TestSince runs the walk over the commits in a scratch repository.
func TestSince(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	vec := filepath.Join(dir, Dir)
	if err := os.MkdirAll(vec, 0o755); err != nil {
		t.Fatal(err)
	}
	commit := func(vector string, write func(*Frozen) *Frozen) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(vec, "a.json"), []byte(vector), 0o644); err != nil {
			t.Fatal(err)
		}
		files, err := Hashes(vec)
		if err != nil {
			t.Fatal(err)
		}
		var old *Frozen
		if b, err := os.ReadFile(filepath.Join(vec, Manifest)); err == nil {
			old, _ = Parse(b)
		}
		next := write(&Frozen{State: "draft", Reason: "-", Hashes: files})
		if old != nil && next.State == "keep" {
			next = old
		}
		if err := os.WriteFile(filepath.Join(vec, Manifest), next.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", "-A")
		git("commit", "-q", "-m", "c")
	}
	git("init", "-q")
	commit("{}", func(f *Frozen) *Frozen { return f })
	git("tag", "base")
	commit("{\"x\":1}", func(f *Frozen) *Frozen { f.State = "frozen"; return f })
	wd, _ := os.Getwd()
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := Since("base"); err != nil {
		t.Fatalf("the freeze: %v", err)
	}
	git("tag", "frozen")
	// A frozen vector changed and the manifest followed, but no break counted.
	commit("{\"x\":2}", func(f *Frozen) *Frozen { f.State = "frozen"; return f })
	if err := Since("frozen"); err == nil || !strings.Contains(err.Error(), "break") {
		t.Fatalf("an uncounted break passed: %v", err)
	}
	git("reset", "-q", "--hard", "frozen")
	// A frozen vector changed and the manifest left as it was.
	commit("{\"x\":3}", func(f *Frozen) *Frozen { f.State = "keep"; return f })
	if err := Since("frozen"); err == nil {
		t.Fatal("a vector changed behind the manifest's back")
	}
	git("reset", "-q", "--hard", "frozen")
	// The one break, counted.
	commit("{\"x\":4}", func(f *Frozen) *Frozen { f.State, f.Breaks, f.Reason = "frozen", 1, "why"; return f })
	if err := Since("frozen"); err != nil {
		t.Fatalf("the counted break: %v", err)
	}
}
