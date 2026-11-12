// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package refused

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	tagA = "0123456789abcdef"
	tagB = "fedcba9876543210"
)

func TestParse(t *testing.T) {
	tags, err := Parse([]byte("# reports\n\n" + tagA + " 2026-11-09 abuse@ report\nperiod " + tagB + "\n  " + tagB + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 3 || !tags[tagA] || !tags[tagB] || !tags["period "+tagB] {
		t.Fatalf("tags = %v", tags)
	}
	for _, bad := range []string{
		"0123456789ABCDEF\n", // cbb status shows lower case
		"0123456789abcde\n",
		"0123456789abcdef0\n",
		"period\n",
		"period xyz\n",
		"group " + tagA + "\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) took it", bad)
		}
	}
}

func TestNilListRefusesNothing(t *testing.T) {
	var l *List
	if l.Refused(tagA) || l.Len() != 0 {
		t.Fatal("a nil list refused a group")
	}
	if changed, err := l.Reload(); changed || err != nil {
		t.Fatalf("Reload = %v, %v", changed, err)
	}
}

func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refused")
	if _, err := Load(""); err == nil {
		t.Fatal("Load took no file")
	}
	l, err := Load(path)
	if err != nil {
		t.Fatalf("a missing file: %v", err)
	}
	if l.Refused(tagA) {
		t.Fatal("an empty list refused a group")
	}
	write := func(s string, age time.Duration) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		// Each write gets its own time, as an editor's would.
		mt := time.Now().Add(-age)
		if err := os.Chtimes(path, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	write(tagA+"\n", 3*time.Minute)
	if changed, err := l.Reload(); !changed || err != nil {
		t.Fatalf("Reload = %v, %v", changed, err)
	}
	if !l.Refused(tagA) || l.Refused(tagB) || l.Len() != 1 {
		t.Fatal("the list is not the file")
	}
	if changed, err := l.Reload(); changed || err != nil {
		t.Fatalf("an unchanged file: Reload = %v, %v", changed, err)
	}

	// A typo keeps the list as it was.
	write(tagA+"\nnot a tag\n", 2*time.Minute)
	if _, err := l.Reload(); err == nil {
		t.Fatal("Reload took a broken file")
	}
	if !l.Refused(tagA) {
		t.Fatal("a broken file let a refused group back in")
	}

	write(tagB+"\n", time.Minute)
	if changed, err := l.Reload(); !changed || err != nil {
		t.Fatalf("Reload = %v, %v", changed, err)
	}
	if l.Refused(tagA) || !l.Refused(tagB) {
		t.Fatal("the list is not the file")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Missing once, as when an editor moves it aside to save it, the list
	// stays; missing again, it is gone.
	if changed, err := l.Reload(); changed || err != nil {
		t.Fatalf("a file moved aside: Reload = %v, %v", changed, err)
	}
	if !l.Refused(tagB) {
		t.Fatal("a file moved aside let a refused group back in")
	}
	if changed, err := l.Reload(); !changed || err != nil {
		t.Fatalf("a removed file: Reload = %v, %v", changed, err)
	}
	if l.Refused(tagB) {
		t.Fatal("a removed file still refuses")
	}

	write(string(make([]byte, maxFile+1)), 0)
	if _, err := l.Reload(); err == nil {
		t.Fatal("Reload took a file too large")
	}
}

func TestOpen(t *testing.T) {
	dir := t.TempDir()
	if l, err := Open("none", filepath.Join(dir, "key")); l != nil || err != nil {
		t.Fatalf("none: %v, %v", l, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "refused-groups"), []byte(tagA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := Open("", filepath.Join(dir, "key"))
	if err != nil || !l.Refused(tagA) {
		t.Fatalf("the list beside the key: %v", err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(other, filepath.Join(dir, "key")); err == nil {
		t.Fatal("Open took a broken list: a server must not start without the list it was given")
	}
}
