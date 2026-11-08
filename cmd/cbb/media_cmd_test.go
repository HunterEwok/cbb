// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
)

// mediaCopy is what a fake service read of a cbb copy of files.
type mediaCopy struct {
	text  string
	parts []control.Part
	data  map[string]string // a file's bytes by its path or type
}

// copyService takes cbb copy FILE's request, its parts and their bytes,
// answers it, or refuses it with refuse, and hands over what it read.
func copyService(t *testing.T, refuse string) chan mediaCopy {
	t.Helper()
	read := make(chan mediaCopy, 1)
	fakeHandler(t, func(m *control.Message, r *control.Reader, c net.Conn) {
		got := mediaCopy{text: string(m.Payload), data: map[string]string{}}
		var current string
		for {
			p, err := r.Read()
			if err != nil {
				return
			}
			switch {
			case p.Op == control.OpPart && p.Done:
				read <- got
				answer(c, control.Message{Header: control.Header{Error: refuse, Done: true}})
				return
			case p.Op == control.OpPart:
				got.parts = append(got.parts, *p.Part)
				current = p.Part.Path + p.Part.Type
			case p.Op == control.OpData:
				got.data[current] += string(p.Payload)
			}
		}
	})
	return read
}

func TestCopyFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	notes := write("notes.txt", "hello")
	write("photos/a.jpg", "jpeg bytes")
	write("photos/deep/b.jpg", "more bytes")

	t.Run("one file", func(t *testing.T) {
		read := copyService(t, "")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"copy", "-text", "alt", notes}, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("copy FILE: %d, %s", code, stderr.String())
		}
		got := <-read
		if got.text != "alt" || len(got.parts) != 1 || got.parts[0].Path != "notes.txt" || got.data["notes.txt"] != "hello" {
			t.Errorf("the service read %+v", got)
		}
		if !strings.Contains(stdout.String(), "Copied notes.txt (5 bytes) to the group.") {
			t.Errorf("stdout %q", stdout.String())
		}
	})
	t.Run("a folder", func(t *testing.T) {
		read := copyService(t, "")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"copy", filepath.Join(dir, "photos"), notes}, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("copy DIR FILE: %d, %s", code, stderr.String())
		}
		got := <-read
		if got.data["photos/deep/b.jpg"] != "more bytes" || got.data["photos/a.jpg"] != "jpeg bytes" {
			t.Errorf("the service read %+v", got)
		}
		if !strings.Contains(stdout.String(), "Copied 3 files in 2 folders") {
			t.Errorf("stdout %q", stdout.String())
		}
	})
	t.Run("an image", func(t *testing.T) {
		read := copyService(t, "")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"copy", "-type", "JPG", notes}, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("copy -type: %d, %s", code, stderr.String())
		}
		got := <-read
		if len(got.parts) != 1 || got.parts[0].Type != clip.TypeJPEG || got.data[clip.TypeJPEG] != "hello" {
			t.Errorf("the service read %+v", got)
		}
		if !strings.Contains(stdout.String(), "Copied the "+clip.TypeJPEG+" (5 bytes)") {
			t.Errorf("stdout %q", stdout.String())
		}
	})
	t.Run("refused", func(t *testing.T) {
		copyService(t, "this device sends copies of at most 1 MiB")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"copy", notes}, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "at most 1 MiB") {
			t.Errorf("a refused copy: %d, %q", code, stderr.String())
		}
	})
	runCommandCases(t, []commandCase{
		{name: "-type with two files", args: []string{"copy", "-type", "png", notes, notes}, code: 2, stderr: "takes one file"},
		{name: "-type of a stranger", args: []string{"copy", "-type", "webp", notes}, code: 2, stderr: "-type is png, jpeg, gif or html"},
		{name: "-type of a folder", args: []string{"copy", "-type", "html", dir}, code: 1, stderr: "is not a file"},
		{name: "-type of nothing", args: []string{"copy", "-type", "png", filepath.Join(dir, "none")}, code: 1},
	})
}

func TestMediaType(t *testing.T) {
	for in, want := range map[string]string{"png": clip.TypePNG, "PNG": clip.TypePNG, "jpeg": clip.TypeJPEG, clip.TypeJPEG: clip.TypeJPEG, "html": clip.TypeHTML, clip.TypeHTML: clip.TypeHTML} {
		if got, err := mediaType(in); err != nil || got != want {
			t.Errorf("mediaType(%q) = %q, %v", in, got, err)
		}
	}
}

// TestPasteFiles saves what the service sends for cbb paste -o, never over
// a file that is there.
func TestPasteFiles(t *testing.T) {
	serve := func(t *testing.T, parts ...control.Message) {
		fakeHandler(t, func(m *control.Message, _ *control.Reader, c net.Conn) {
			if m.Op != control.OpPasteMedia {
				return
			}
			answer(c, control.Message{})
			for _, p := range parts {
				answer(c, p)
			}
			answer(c, control.Message{Header: control.Header{Done: true}})
		})
	}
	part := func(p control.Part) control.Message { return control.Message{Header: control.Header{Part: &p}} }
	data := func(s string) control.Message { return control.Message{Payload: []byte(s)} }

	dir := t.TempDir()
	serve(t, part(control.Part{Path: "docs", Dir: true}), part(control.Part{Path: "docs/a.txt", Size: 3}), data("abc"), part(control.Part{Type: clip.TypePNG, Size: 2}), data("pn"))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"paste", "-o", dir}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("paste -o: %d, %s", code, stderr.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "docs", "a.txt")); string(b) != "abc" {
		t.Errorf("docs/a.txt holds %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "image.png")); string(b) != "pn" {
		t.Errorf("image.png holds %q", b)
	}
	if want := filepath.Join(dir, "docs") + "\n" + filepath.Join(dir, "image.png") + "\n"; stdout.String() != want {
		t.Errorf("stdout %q, want %q", stdout.String(), want)
	}

	// Again: image.png is there now, so nothing is replaced and what the
	// second paste made is taken away.
	serve(t, part(control.Part{Path: "b.txt", Size: 1}), data("b"), part(control.Part{Type: clip.TypePNG, Size: 2}), data("xx"))
	stdout.Reset()
	if code := run([]string{"paste", "-o", dir}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Errorf("paste -o over a file: %d", code)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "image.png")); string(b) != "pn" {
		t.Errorf("image.png became %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.txt")); !os.IsNotExist(err) {
		t.Errorf("the failed paste left b.txt: %v", err)
	}
	stderr.Reset()
	if code := run([]string{"paste", "-o", filepath.Join(dir, "docs", "a.txt")}, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "is not a folder") {
		t.Errorf("paste -o FILE: %d, %q", code, stderr.String())
	}
}

func TestWriteMedia(t *testing.T) {
	for _, c := range []struct {
		m    *control.Media
		want string
	}{
		{nil, ""},
		{&control.Media{}, ""},
		{&control.Media{Fetching: 200, Fetched: 50, From: "laptop"}, "Fetching a copy of 200 bytes from laptop: 25%.\n"},
		{&control.Media{Fetching: 10, Fetched: 10}, "Fetching a copy of 10 bytes: 100%.\n"},
		{&control.Media{Failed: "it is larger than 1 MiB"}, "The last copy of images or files was not fetched: it is larger than 1 MiB.\n"},
	} {
		var b bytes.Buffer
		writeMedia(&b, c.m)
		if b.String() != c.want {
			t.Errorf("writeMedia(%+v) = %q, want %q", c.m, b.String(), c.want)
		}
	}
}
