// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/mediafile"
)

// fileBoard is a fake clipboard that takes files.
type fileBoard struct {
	*fakeBoard
	files chan []string
}

func (b *fileBoard) WriteFiles(paths []string) error {
	b.mu.Lock()
	b.item, b.has, b.ownWrite = Item{Files: paths}, true, true
	b.mu.Unlock()
	b.files <- paths
	return nil
}

// copyFiles copies files on the service as cbb copy does.
func copyFiles(t *testing.T, socket string, paths ...string) {
	t.Helper()
	parts, _, err := mediafile.Collect(paths)
	if err != nil {
		t.Fatal(err)
	}
	c, err := control.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := mediafile.Send(c, control.OpCopyMedia, parts, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Receive(); err != nil {
		t.Fatal(err)
	}
}

// pasted saves the service's copy in a new folder, as cbb paste -o does,
// and returns what each file holds by its path there.
func pasted(t *testing.T, socket string) (map[string]string, error) {
	c, err := control.Dial(socket)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPasteMedia}}); err != nil {
		return nil, err
	}
	dir := t.TempDir()
	if _, err := mediafile.Save(c, dir); err != nil {
		return nil, err
	}
	return tree(t, dir), nil
}

// tree returns what each file under dir holds by its slash path.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	got := map[string]string{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			b, _ := os.ReadFile(p)
			got[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	return got
}

// TestFiles: files copied on the desktop reach the service, and files
// copied with cbb copy reach the desktop, saved in a folder of their own
// that stays a while after a newer copy.
func TestFiles(t *testing.T) {
	old := KeepCopies
	KeepCopies = 200 * time.Millisecond
	t.Cleanup(func() { KeepCopies = old })
	socket := startService(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "left over"), []byte("x"), 0o600)
	b := &fileBoard{fakeBoard: newBoard(), files: make(chan []string, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Config{Socket: socket, Board: b, Files: root, Logf: t.Logf}) }()
	t.Cleanup(func() { cancel(); <-done })
	b.copyOn(Item{Text: "the board watches"})
	waitFor(t, "the board", func() bool { return paste(t, socket) == "the board watches" })
	if _, err := os.Stat(filepath.Join(root, "left over")); err == nil {
		t.Error("the files of an earlier run were kept")
	}

	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "trip", "day 1"), 0o755)
	os.WriteFile(filepath.Join(src, "trip", "day 1", "a.jpg"), []byte("jpeg"), 0o644)
	os.WriteFile(filepath.Join(src, "notes.txt"), []byte("notes"), 0o644)
	b.copyOn(Item{Files: []string{filepath.Join(src, "trip"), filepath.Join(src, "notes.txt")}})
	want := map[string]string{"trip/day 1/a.jpg": "jpeg", "notes.txt": "notes"}
	waitFor(t, "the desktop's files", func() bool {
		got, err := pasted(t, socket)
		return err == nil && maps.Equal(got, want)
	})

	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "report.pdf"), []byte("pdf"), 0o644)
	copyFiles(t, socket, filepath.Join(other, "report.pdf"))
	first := expectFiles(t, b, map[string]string{"report.pdf": "pdf"})

	os.WriteFile(filepath.Join(other, "second.txt"), []byte("2"), 0o644)
	copyFiles(t, socket, filepath.Join(other, "second.txt"))
	expectFiles(t, b, map[string]string{"second.txt": "2"})
	if _, err := os.Stat(first); err != nil {
		t.Errorf("the older copy went at once: %v", err)
	}
	waitFor(t, "the older copy to go", func() bool {
		_, err := os.Stat(first)
		return os.IsNotExist(err)
	})

	// A text after the files replaces them.
	do(t, socket, control.Header{Op: control.OpCopy}, "a text again")
	expectWrite(t, b.fakeBoard, "a text again", false)
}

// expectFiles waits for a WriteFiles of a copy that holds want, in a
// folder of its own readable only by the user, and returns that folder.
func expectFiles(t *testing.T, b *fileBoard, want map[string]string) string {
	t.Helper()
	select {
	case paths := <-b.files:
		dir := filepath.Dir(paths[0])
		for _, p := range paths {
			if filepath.Dir(p) != dir {
				t.Errorf("the copy's files are in %s and %s", dir, filepath.Dir(p))
			}
		}
		if got := tree(t, dir); !maps.Equal(got, want) {
			t.Errorf("the desktop got %v, want %v", got, want)
		}
		if info, err := os.Stat(dir); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
			t.Errorf("the copy's folder: %v, %v", info.Mode(), err)
		}
		return dir
	case <-time.After(5 * time.Second):
		t.Fatal("the files did not reach the desktop")
		return ""
	}
}
