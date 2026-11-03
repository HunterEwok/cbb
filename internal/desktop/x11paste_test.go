// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
		t.Skip("xterm is not installed")
	}
	t.Setenv("WAYLAND_DISPLAY", "")
	dir := t.TempDir()
	out, idFile := filepath.Join(dir, "out"), filepath.Join(dir, "id")
	xterm := exec.Command("xterm", "-u8", "-e", "sh", "-c", `echo "$WINDOWID" >"$1"; stty -echo; exec cat >"$2"`, "sh", idFile, out)
	xterm.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	if err := xterm.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { xterm.Process.Kill(); xterm.Wait() }()
	var win uint64
	for range 100 {
		if b, err := os.ReadFile(idFile); err == nil && len(b) > 0 {
			win, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if win == 0 {
		t.Fatal("xterm did not start")
	}

	b, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Target() != "desktop" {
		t.Fatalf("Target = %q", b.Target())
	}
	time.Sleep(300 * time.Millisecond) // xterm maps its window
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
	want := "pasted \u00e9 \u03b1\u03b2\u03b3\u20ac\ntyped Text: \u00e9 \u03b1\u03b2\u03b3\u20ac & ~|\na secret\n"
	var got []byte
	for range 50 {
		if got, _ = os.ReadFile(out); string(got) == want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if string(got) != want {
		t.Errorf("xterm got %q, want %q", got, want)
	}
	// The screen saver on refuses a paste.
	xproto.ForceScreenSaver(b.x, xproto.ScreenSaverActive)
	err = b.Inject(ctx, "not while locked", "paste", false, false)
	xproto.ForceScreenSaver(b.x, xproto.ScreenSaverReset)
	var r *connector.Refusal
	if !errors.As(err, &r) {
		t.Errorf("a paste with the screen saver on: %v", err)
	}
	// Typing leaves the keyboard mapping as it was.
	keys, err := b.keyboard()
	if err != nil {
		t.Fatal(err)
	}
	if code := keys.mapped(runeKeysym('\u03b1')); code != 0 {
		t.Errorf("keycode %d still types a character of the text", code)
	}
}
