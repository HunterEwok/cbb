// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestX11 runs against a real X server, such as Xvfb, and checks the
// connector's view against xclip. It runs only when CBB_TEST_X11 is
// set, for example in a container.
func TestX11(t *testing.T) {
	if os.Getenv("CBB_TEST_X11") == "" {
		t.Skip("set CBB_TEST_X11 with an X server in DISPLAY and xclip installed")
	}
	b, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	xclipIn := func(text string) {
		t.Helper()
		cmd := exec.Command("xclip", "-selection", "clipboard", "-i")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			t.Fatalf("xclip -i: %v", err)
		}
	}
	xclipOut := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("xclip", append([]string{"-selection", "clipboard", "-o"}, args...)...).Output()
		if err != nil {
			t.Fatalf("xclip -o %v: %v", args, err)
		}
		return string(out)
	}

	xclipIn("copied by xclip")
	it, ok, err := b.Next(ctx)
	if err != nil || !ok || it.Text != "copied by xclip" {
		t.Fatalf("Next = %+v, %v, %v", it, ok, err)
	}

	text := "written by cbb \u043f\u0440\u0438\u0432\u0435\u0442\nline two"
	if err := b.Write(text, false); err != nil {
		t.Fatal(err)
	}
	if got := xclipOut(); got != text {
		t.Errorf("xclip -o = %q, want %q", got, text)
	}
	if out, err := exec.Command("xclip", "-selection", "primary", "-o").Output(); err != nil || string(out) != text {
		t.Errorf("primary = %q, %v", out, err)
	}
	if targets := xclipOut("-t", "TARGETS"); !strings.Contains(targets, "UTF8_STRING") || strings.Contains(targets, secretType) {
		t.Errorf("targets:\n%s", targets)
	}
	select {
	case it := <-b.changes:
		t.Errorf("our own write came back as a change: %+v", it)
	case <-time.After(500 * time.Millisecond):
	}

	// A large text goes out in INCR pieces and comes in the same way.
	big := strings.Repeat("0123456789abcdef", 600_000/16)
	if err := b.Write(big, false); err != nil {
		t.Fatal(err)
	}
	if got := xclipOut(); got != big {
		t.Errorf("xclip read %d bytes of %d", len(got), len(big))
	}
	big2 := strings.Repeat("fedcba9876543210", 500_000/16)
	xclipIn(big2)
	it, ok, err = b.Next(ctx)
	if err != nil || !ok || it.Text != big2 {
		t.Fatalf("Next of a large copy = %d bytes, %v, %v", len(it.Text), ok, err)
	}

	// A secret is offered with the hint, and given up when it expires.
	if err := b.Write("hunter2", true); err != nil {
		t.Fatal(err)
	}
	if targets := xclipOut("-t", "TARGETS"); !strings.Contains(targets, secretType) {
		t.Errorf("a secret's targets:\n%s", targets)
	}
	if err := b.ClearIfUnchanged(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("xclip", "-selection", "clipboard", "-o").Output(); err == nil && string(out) == "hunter2" {
		t.Error("the secret is still in the clipboard")
	}

	// A marked copy from another program is reported as a secret.
	cmd := exec.Command("xclip", "-selection", "clipboard", "-t", secretType, "-i")
	cmd.Stdin = strings.NewReader("secret")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	// xclip offers only the hint type here, so there is no text to read.
	select {
	case it := <-b.changes:
		if !it.Secret {
			t.Errorf("a marked copy was reported as %+v", it)
		}
	case <-time.After(time.Second):
	}
}

func TestX11Writes(t *testing.T) {
	if os.Getenv("CBB_TEST_X11") == "" {
		t.Skip("set CBB_TEST_X11 with an X server in DISPLAY and xclip installed")
	}
	// What the clipboard holds at open is known, but no change.
	cmd := exec.Command("xclip", "-selection", "clipboard", "-i")
	cmd.Stdin = strings.NewReader("there before")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	b, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if it, ok, _ := b.Current(); !ok || it.Text != "there before" {
		t.Errorf("Current = %+v, %v", it, ok)
	}
	select {
	case it := <-b.changes:
		t.Errorf("the clipboard at open came as a change: %+v", it)
	case <-time.After(300 * time.Millisecond):
	}
	for i := range 50 {
		if err := b.Write(strings.Repeat("x", i)+"end", false); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("xclip", "-selection", "clipboard", "-o").Output()
	if err != nil || string(out) != strings.Repeat("x", 49)+"end" {
		t.Errorf("xclip -o = %q, %v", out, err)
	}
	select {
	case it := <-b.changes:
		t.Errorf("our own write came back as a change: %+v", it)
	case <-time.After(300 * time.Millisecond):
	}
	// An expired secret given up while a large transfer runs leaves no copy
	// of it behind.
	if err := b.Write(strings.Repeat("s", 300_000), true); err != nil {
		t.Fatal(err)
	}
	if err := b.ClearIfUnchanged(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if out, _ := exec.Command("xclip", "-selection", "clipboard", "-o").Output(); len(out) > 0 {
		t.Errorf("the clipboard still holds %d bytes", len(out))
	}
}
