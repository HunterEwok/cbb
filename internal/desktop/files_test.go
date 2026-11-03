// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/HunterEwok/cbb/internal/connector"
)

func TestFilePaths(t *testing.T) {
	for _, c := range []struct {
		typ, data string
		want      []string
	}{
		{uriListType, "file:///home/u/a%20b.txt\r\n# a comment\r\nfile://localhost/etc/hosts\r\n", []string{"/home/u/a b.txt", "/etc/hosts"}},
		{gnomeFilesType, "copy\nfile:///tmp/x\nfile:///tmp/y", []string{"/tmp/x", "/tmp/y"}},
		{gnomeFilesType, "cut\nfile:///tmp/x", []string{"/tmp/x"}},
		{uriListType, "https://example.com/\r\nfile://other-host/etc/passwd\r\nfile:relative\r\n", nil},
		{uriListType, "file:///tmp/../etc/./hosts", []string{"/etc/hosts"}},
	} {
		if got := filePaths(c.typ, []byte(c.data)); !slices.Equal(got, c.want) {
			t.Errorf("filePaths(%q) = %q, want %q", c.data, got, c.want)
		}
	}
	paths := []string{"/home/u/a b.txt", "/tmp/50%"}
	data := fileData(paths, "key")
	if got := string(data[uriListType]); got != "file:///home/u/a%20b.txt\r\nfile:///tmp/50%25\r\n" {
		t.Errorf("text/uri-list = %q", got)
	}
	for _, typ := range fileTypes {
		if got := filePaths(typ, data[typ]); !slices.Equal(got, paths) {
			t.Errorf("%s does not read back: %q", typ, got)
		}
	}
	if got := string(data[portalFilesType]); got != "key" {
		t.Errorf("the portal's key is %q", got)
	}
}

// fakeTransfer plays the document portal's FileTransfer. godbus cannot
// decode an array of descriptors it receives: its decoder stops there and
// keeps only the arguments before it (the real portal, in C, takes them;
// dbus-monitor shows they are sent right), so the fake takes AddFiles'
// key and counts the descriptors the message carried.
type fakeTransfer struct {
	mu      sync.Mutex
	n       int
	files   map[string]int
	stopped []string
}

func (f *fakeTransfer) StartTransfer(opts map[string]dbus.Variant) (string, *dbus.Error) {
	if auto, _ := opts["autostop"].Value().(bool); auto {
		return "", dbus.MakeFailedError(fmt.Errorf("autostop would end the transfer at the first paste"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return fmt.Sprintf("key-%d", f.n), nil
}

func (f *fakeTransfer) AddFiles(m dbus.Message, key string) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, _ := m.Headers[dbus.FieldUnixFDs].Value().(uint32)
	f.files[key] += int(n)
	return nil
}

func (f *fakeTransfer) StopTransfer(key string) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, key)
	return nil
}

// TestTransfers: written files go to the FileTransfer portal, and the
// transfer of the last ones stops when new ones come.
func TestTransfers(t *testing.T) {
	addr := startBus(t)
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	f := &fakeTransfer{files: map[string]int{}}
	if err := conn.Export(f, docsPath, fileTransfer); err != nil {
		t.Fatal(err)
	}
	if r, err := conn.RequestName(docsBus, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("taking the portal's name: %v %v", r, err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b dir")
	os.WriteFile(a, []byte("a"), 0o600)
	os.Mkdir(b, 0o700)

	tr := &transfers{logf: t.Logf}
	defer tr.close()
	if key := tr.start([]string{a, b}); key != "key-1" {
		t.Fatalf("the first transfer's key is %q", key)
	}
	if key := tr.start([]string{a}); key != "key-2" {
		t.Fatalf("the second transfer's key is %q", key)
	}
	tr.stop()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.files["key-1"] != 2 || f.files["key-2"] != 1 {
		t.Errorf("the portal got %v", f.files)
	}
	if !slices.Equal(f.stopped, []string{"key-1", "key-2"}) {
		t.Errorf("stopped %v", f.stopped)
	}
}

// fileBoard is a board under test that takes files.
type fileBoard interface {
	connector.Board
	connector.FileBoard
}

// testFiles copies lists of files with a tool and reads them, writes some
// and pastes them with the tool in every type.
func testFiles(t *testing.T, b fileBoard, copyAs func(typ string, data []byte), paste func(typ string) []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	copyAs(uriListType, []byte("file:///home/u/a%20b.txt\r\nfile:///home/u/trip\r\n"))
	it, ok, err := b.Next(ctx)
	if err != nil || !ok || !slices.Equal(it.Files, []string{"/home/u/a b.txt", "/home/u/trip"}) {
		t.Fatalf("Next after a copy of files = %q, %v, %v", it.Files, ok, err)
	}
	copyAs(gnomeFilesType, []byte("cut\nfile:///tmp/x"))
	if it, ok, err := b.Next(ctx); err != nil || !ok || !slices.Equal(it.Files, []string{"/tmp/x"}) {
		t.Fatalf("Next after a cut in GNOME's type = %q, %v, %v", it.Files, ok, err)
	}

	paths := []string{"/home/u/report 1.pdf", "/home/u/photos"}
	if err := b.WriteFiles(paths); err != nil {
		t.Fatal(err)
	}
	data := fileData(paths, "")
	for _, typ := range fileTypes {
		if got := paste(typ); !bytes.Equal(got, data[typ]) {
			t.Errorf("pasted %s %q, want %q", typ, got, data[typ])
		}
	}
	if got := string(paste("text/plain")); got != strings.Join(paths, "\n") {
		t.Errorf("pasted the text %q", got)
	}
	ctx2, cancel2 := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel2()
	if it, ok, err := b.Next(ctx2); err == nil {
		t.Errorf("our write of files came back: %q, %v", it.Files, ok)
	}
}

func TestX11Files(t *testing.T) {
	if os.Getenv("CBB_TEST_X11") == "" {
		t.Skip("set CBB_TEST_X11 with an X server in DISPLAY and xclip installed")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent") // no portal
	b, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	testFiles(t, b, func(typ string, data []byte) {
		cmd := exec.Command("xclip", "-selection", "clipboard", "-t", typ, "-i")
		cmd.Stdin = bytes.NewReader(data)
		if err := cmd.Run(); err != nil {
			t.Fatalf("xclip -i: %v", err)
		}
	}, func(typ string) []byte {
		out, err := exec.Command("xclip", "-selection", "clipboard", "-t", typ, "-o").Output()
		if err != nil {
			t.Errorf("xclip -t %s -o: %v", typ, err)
		}
		return out
	})
}

func TestWaylandFiles(t *testing.T) {
	if os.Getenv("CBB_TEST_WAYLAND") == "" {
		t.Skip("set CBB_TEST_WAYLAND in a session with a data-control compositor and wl-clipboard")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent") // no portal
	w, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	testFiles(t, w, func(typ string, data []byte) {
		cmd := exec.Command("wl-copy", "--type", typ)
		cmd.Stdin = bytes.NewReader(data)
		if err := cmd.Run(); err != nil {
			t.Fatalf("wl-copy: %v", err)
		}
	}, func(typ string) []byte {
		out, err := exec.Command("wl-paste", "--no-newline", "--type", typ).Output()
		if err != nil {
			t.Errorf("wl-paste --type %s: %v", typ, err)
		}
		return out
	})
}
