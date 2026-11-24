// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"

	"github.com/HunterEwok/cbb/internal/connector"
)

// TestX11Paste pastes and types into an xterm that writes what it gets to
// a file. It runs only when CBB_TEST_X11 is set and xterm is installed.
func TestX11Paste(t *testing.T) {
	if os.Getenv("CBB_TEST_X11") == "" {
		t.Skip("set CBB_TEST_X11 with an X server in DISPLAY and xterm installed")
	}
	if _, err := exec.LookPath("xterm"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("xterm is not installed")
		}
		t.Skip("xterm is not installed")
	}
	t.Setenv("WAYLAND_DISPLAY", "")
	dir := t.TempDir()
	// Both are pipes: a read waits for what xterm writes.
	out, idFile := filepath.Join(dir, "out"), filepath.Join(dir, "id")
	for _, f := range []string{out, idFile} {
		if err := syscall.Mkfifo(f, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	xterm := exec.Command("xterm", "-u8", "-e", "sh", "-c", `echo "$WINDOWID" >"$1"; stty -echo; exec cat >"$2"`, "sh", idFile, out)
	xterm.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	if err := xterm.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { xterm.Process.Kill(); xterm.Wait() }()
	id, err := os.ReadFile(idFile)
	if err != nil {
		t.Fatal(err)
	}
	win, err := strconv.ParseUint(strings.TrimSpace(string(id)), 10, 32)
	if err != nil {
		t.Fatalf("xterm's window %q: %v", id, err)
	}
	mapped(t, xproto.Window(win))

	b, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Target() != "desktop" {
		t.Fatalf("Target = %q", b.Target())
	}
	if err := xproto.SetInputFocusChecked(b.x, xproto.InputFocusPointerRoot, xproto.Window(win), xproto.TimeCurrentTime).Check(); err != nil {
		t.Fatal(err)
	}
	if err := b.Write("there before", false); err != nil {
		t.Fatal(err)
	}
	// The test's session is none that logind knows: the paste goes in as
	// on a device whose user allowed that.
	ctx := connector.WithoutLockCheck(context.Background(), true)
	if err := b.Inject(ctx, "pasted \u00e9 \u03b1\u03b2\u03b3\u20ac", "paste", true, false); err != nil {
		t.Fatal(err)
	}
	if it, ok, _ := b.Current(); !ok || it.Text != "there before" {
		t.Errorf("the clipboard after a paste holds %+v, %v", it, ok)
	}
	if err := b.Inject(ctx, "typed Text: \u00e9 \u03b1\u03b2\u03b3\u20ac & ~|", "type", true, false); err != nil {
		t.Fatal(err)
	}
	if err := b.Inject(ctx, "a secret", "paste", true, true); err != nil {
		t.Fatal(err)
	}
	// Images and files go in through the clipboard the same way: here a
	// text stands in for them.
	if err := b.InjectMedia(ctx, func() error { return b.Write("as media", false) }, true); err != nil {
		t.Fatal(err)
	}
	if err := b.InjectMedia(ctx, func() error { return errors.New("no media") }, true); err == nil {
		t.Error("pasted media it could not write")
	}
	want := "pasted \u00e9 \u03b1\u03b2\u03b3\u20ac\ntyped Text: \u00e9 \u03b1\u03b2\u03b3\u20ac & ~|\na secret\nas media\n"
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := make([]byte, len(want))
	io.ReadFull(f, got)
	if string(got) != want {
		t.Errorf("xterm got %q, want %q", got, want)
	}
	// The screen saver on refuses a paste.
	xproto.ForceScreenSaver(b.x, xproto.ScreenSaverActive)
	err = b.Inject(ctx, "not while locked", "paste", false, false)
	merr := b.InjectMedia(ctx, func() error { return nil }, false)
	xproto.ForceScreenSaver(b.x, xproto.ScreenSaverReset)
	var r *connector.Refusal
	if !errors.As(err, &r) {
		t.Errorf("a paste with the screen saver on: %v", err)
	}
	if !errors.As(merr, &r) {
		t.Errorf("media with the screen saver on: %v", merr)
	}
	// Under XWayland with no way to press keys, media is refused.
	t.Setenv("WAYLAND_DISPLAY", "wayland-none")
	if err := b.InjectMedia(ctx, func() error { return nil }, false); !errors.As(err, &r) {
		t.Errorf("media under Wayland without keys: %v", err)
	}
	t.Setenv("WAYLAND_DISPLAY", "")
	// Typing leaves the keyboard mapping as it was.
	keys, err := b.keyboard()
	if err != nil {
		t.Fatal(err)
	}
	if code := keys.mapped(runeKeysym('\u03b1')); code != 0 {
		t.Errorf("keycode %d still types a character of the text", code)
	}
}

// mapped waits until the window is mapped: it asks for the window's
// structure events before it looks, so the map is seen either way.
func mapped(t *testing.T, win xproto.Window) {
	t.Helper()
	x, err := xgb.NewConn()
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if err := xproto.ChangeWindowAttributesChecked(x, win, xproto.CwEventMask, []uint32{xproto.EventMaskStructureNotify}).Check(); err != nil {
		t.Fatal(err)
	}
	a, err := xproto.GetWindowAttributes(x, win).Reply()
	if err != nil {
		t.Fatal(err)
	}
	for a.MapState != xproto.MapStateViewable {
		ev, err := x.WaitForEvent()
		if ev == nil && err == nil {
			t.Fatal("the X connection ended")
		}
		if _, ok := ev.(xproto.MapNotifyEvent); ok {
			return
		}
	}
}
