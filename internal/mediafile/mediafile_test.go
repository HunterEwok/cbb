// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mediafile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

func TestCollect(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "trip")
	os.MkdirAll(filepath.Join(tree, "day 1"), 0o755)
	os.WriteFile(filepath.Join(tree, "day 1", "a.jpg"), []byte("jpeg"), 0o644)
	os.WriteFile(filepath.Join(tree, "notes."), []byte("x"), 0o644) // Windows cannot hold this name
	single := filepath.Join(dir, "con.txt")
	os.WriteFile(single, []byte("hi"), 0o644)
	links := 0
	if runtime.GOOS != "windows" {
		os.Symlink("/etc/passwd", filepath.Join(tree, "link"))
		links = 1
	}
	parts, skipped, err := Collect([]string{tree, single})
	if err != nil {
		t.Fatal(err)
	}
	if skipped != links {
		t.Errorf("left out %d, want %d", skipped, links)
	}
	notes := "trip/notes._"
	if runtime.GOOS == "windows" {
		notes = "trip/notes" // Windows drops the trailing dot when it creates the file
	}
	want := []control.Part{{Path: "trip", Dir: true}, {Path: "trip/day 1", Dir: true}, {Path: "trip/day 1/a.jpg", Size: 4}, {Path: notes, Size: 1}, {Path: "con_.txt", Size: 2}}
	if len(parts) != len(want) {
		t.Fatalf("parts %+v", parts)
	}
	for i, p := range parts {
		if p.Part != want[i] {
			t.Errorf("part %d = %+v, want %+v", i, p.Part, want[i])
		}
	}
	if _, _, err := Collect([]string{single, single}); err == nil {
		t.Error("the same file twice was taken")
	}
	for _, p := range []control.Part{{Path: "../x"}, {Path: "/etc/x"}, {Type: "image/gif"}} {
		if _, err := SavedName(p); err == nil {
			t.Errorf("SavedName(%+v) succeeded", p)
		}
	}
	if name, err := SavedName(control.Part{Type: "image/png"}); err != nil || name != "image.png" {
		t.Errorf("savedName of an image = %q, %v", name, err)
	}
}
