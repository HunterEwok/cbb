// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/control"
)

// TestLiteClients: the Go command line and the desktop's clipboard agent
// work against the Rust service as against the Go one: cbb status, config,
// copy and paste of texts and files, and an agent whose clipboard takes
// images (docs/design.md, "The service and its helper"). CBB_LITE names
// the Rust member's binary.
func TestLiteClients(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := goCLI(t)
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
	lite := startLite(t, bin, dir, "-no-mdns", "-peer", pi.addr())
	waitFor(t, "the Rust member connected", func() bool {
		st, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1
	})
	if _, err := lite.do(t, control.Header{Op: control.OpMode, Name: "shared"}, ""); err != nil {
		t.Fatal(err)
	}
	run := func(stdin string, args ...string) (string, error) {
		t.Helper()
		return runCLI(cli, lite.socket, stdin, args...)
	}
	must := func(stdin string, args ...string) string {
		t.Helper()
		out, err := run(stdin, args...)
		if err != nil {
			t.Fatalf("cbb %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}

	if out := must("", "status"); !strings.Contains(out, "pi") {
		t.Errorf("cbb status does not list pi:\n%s", out)
	}
	if out := must("", "config"); !strings.Contains(out, "max-copy       100 MiB") || !strings.Contains(out, "max-copy-away  25 MiB") {
		t.Errorf("cbb config:\n%s", out)
	}
	if out := must("", "config", "max-copy", "10MiB"); !strings.Contains(out, "max-copy       10 MiB") || !strings.Contains(out, "max-copy-away  10 MiB") {
		t.Errorf("cbb config max-copy 10MiB:\n%s", out)
	}
	if out, err := run("", "config", "max-copy-away", "20MiB"); err == nil || !strings.Contains(out, "max-copy-away must be") {
		t.Errorf("cbb config max-copy-away above max-copy: %v\n%s", err, out)
	}

	// Texts both ways.
	must("from the command line", "copy")
	waitFor(t, "pi has the text", func() bool { return pi.paste(t) == "from the command line" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from pi"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "cbb paste has pi's text", func() bool { out, err := run("", "paste"); return err == nil && out == "from pi" })

	// Files both ways.
	src := t.TempDir()
	big := randomBytes(2<<20 + 3)
	os.MkdirAll(filepath.Join(src, "photos"), 0o755)
	os.WriteFile(filepath.Join(src, "photos", "one.jpg"), big, 0o644)
	os.WriteFile(filepath.Join(src, "notes.txt"), []byte("hello"), 0o644)
	must("", "copy", "-text", "photos and notes", filepath.Join(src, "photos"), filepath.Join(src, "notes.txt"))
	waitFor(t, "pi has the files", func() bool {
		text, parts, err := pi.pasteMedia(t)
		if err != nil || text != "photos and notes" || len(parts) != 3 {
			return false
		}
		return parts[0].Dir && bytes.Equal(parts[1].data, big) && string(parts[2].data) == "hello"
	})
	if err := pi.copyMedia(t, "", file("from-pi.txt", []byte("pi's file"))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "cbb paste says the copy is files", func() bool {
		out, err := run("", "paste")
		return err != nil && strings.Contains(out, "cbb paste -o DIR saves them")
	})
	saved := t.TempDir()
	must("", "paste", "-o", saved)
	if b, err := os.ReadFile(filepath.Join(saved, "from-pi.txt")); err != nil || string(b) != "pi's file" {
		t.Errorf("cbb paste -o saved %q, %v", b, err)
	}

	// The desktop's agent: texts and images both ways.
	b := &agentBoard{changes: make(chan connector.Item, 4), writes: make(chan connector.Item, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- connector.Run(ctx, connector.Config{Socket: lite.socket, Board: b, Logf: t.Logf}) }()
	t.Cleanup(func() { cancel(); <-done })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the agent"); err != nil {
		t.Fatal(err)
	}
	if it := b.next(t); it.Text != "to the agent" {
		t.Fatalf("the agent wrote %+v, want pi's text", it)
	}
	b.changes <- connector.Item{Text: "from the agent"}
	waitFor(t, "pi has the agent's text", func() bool { return pi.paste(t) == "from the agent" })
	png := randomBytes(1<<20 + 9)
	if err := pi.copyMedia(t, "a picture", sentPart{Part: control.Part{Type: clip.TypePNG, Size: int64(len(png))}, data: png}); err != nil {
		t.Fatal(err)
	}
	if it := b.next(t); it.Image == nil || it.Image.Type != clip.TypePNG || !bytes.Equal(it.Image.Data, png) || it.Text != "a picture" {
		t.Fatalf("the agent wrote %+v, want pi's picture", it.Text)
	}
	jpeg := randomBytes(4096)
	b.changes <- connector.Item{Image: &connector.Image{Type: clip.TypeJPEG, Data: jpeg}}
	waitFor(t, "pi has the agent's picture", func() bool {
		_, parts, err := pi.pasteMedia(t)
		return err == nil && len(parts) == 1 && parts[0].Type == clip.TypeJPEG && bytes.Equal(parts[0].data, jpeg)
	})
}

// agentBoard is a desktop clipboard that takes images, which the test
// changes by hand.
type agentBoard struct {
	mu      sync.Mutex
	item    connector.Item
	has     bool
	changes chan connector.Item
	writes  chan connector.Item
}

func (b *agentBoard) Current() (connector.Item, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.item, b.has, nil
}

func (b *agentBoard) Next(ctx context.Context) (connector.Item, bool, error) {
	select {
	case it := <-b.changes:
		b.set(it)
		return it, true, nil
	case <-ctx.Done():
		return connector.Item{}, false, ctx.Err()
	}
}

func (b *agentBoard) set(it connector.Item) {
	b.mu.Lock()
	b.item, b.has = it, true
	b.mu.Unlock()
}

func (b *agentBoard) Write(text string, secret bool) error {
	it := connector.Item{Text: text, Secret: secret}
	b.set(it)
	b.writes <- it
	return nil
}

func (b *agentBoard) WriteImage(img connector.Image, text string) error {
	it := connector.Item{Text: text, Image: &img}
	b.set(it)
	b.writes <- it
	return nil
}

func (b *agentBoard) ClearIfUnchanged() error { return nil }

// next is the next write the agent made.
func (b *agentBoard) next(t *testing.T) connector.Item {
	t.Helper()
	var it connector.Item
	waitFor(t, "the agent writes", func() bool {
		select {
		case it = <-b.writes:
			return true
		default:
			return false
		}
	})
	return it
}
