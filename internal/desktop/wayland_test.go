// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/cbb/internal/wl"
)

// TestWayland runs against a real compositor with data-control, such as a
// headless sway, and checks the connector's view against wl-clipboard. It
// runs only when CBB_TEST_WAYLAND is set, for example in a
// container.
func TestWayland(t *testing.T) {
	if os.Getenv("CBB_TEST_WAYLAND") == "" {
		t.Skip("set CBB_TEST_WAYLAND in a session with a data-control compositor and wl-clipboard")
	}
	w, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// wl-copy forks a child that serves the selection; its output is not
	// captured, or the pipes would stay open.
	wlCopy := func(text string) {
		t.Helper()
		if err := exec.Command("wl-copy", text).Run(); err != nil {
			t.Fatalf("wl-copy: %v", err)
		}
	}
	// Another program copies: the connector sees it.
	wlCopy("copied by wl-copy")
	it, ok, err := w.Next(ctx)
	if err != nil || !ok || it.Text != "copied by wl-copy" || it.Secret {
		t.Fatalf("Next = %+v, %v, %v", it, ok, err)
	}

	// The connector writes: other programs paste it, from the clipboard and
	// from the primary selection, and the write does not come back as a
	// change.
	text := "written by cbb \u043f\u0440\u0438\u0432\u0435\u0442\nline two"
	if err := w.Write(text, false); err != nil {
		t.Fatal(err)
	}
	paste := func(args ...string) string {
		out, err := exec.Command("wl-paste", append([]string{"--no-newline"}, args...)...).Output()
		if err != nil {
			t.Fatalf("wl-paste %v: %v", args, err)
		}
		return string(out)
	}
	if got := paste(); got != text {
		t.Errorf("wl-paste = %q, want %q", got, text)
	}
	if got := paste("--primary"); got != text {
		t.Errorf("wl-paste --primary = %q", got)
	}
	types := paste("--list-types")
	if !strings.Contains(types, "text/plain;charset=utf-8") || !strings.Contains(types, "UTF8_STRING") {
		t.Errorf("offered types:\n%s", types)
	}
	select {
	case it := <-w.changes:
		t.Errorf("our own write came back as a change: %+v", it)
	case <-time.After(500 * time.Millisecond):
	}

	// A secret carries the hint, so clipboard managers skip it.
	if err := w.Write("hunter2", true); err != nil {
		t.Fatal(err)
	}
	if types := paste("--list-types"); !strings.Contains(types, "x-kde-passwordManagerHint") {
		t.Errorf("a secret offered only:\n%s", types)
	}
	// Giving up an expired secret empties the clipboard.
	if err := w.ClearIfUnchanged(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if out, err := exec.Command("wl-paste", "--no-newline").Output(); err == nil && string(out) == "hunter2" {
		t.Error("the secret is still in the clipboard")
	}

	// A copy after ours is seen again.
	wlCopy("after the secret")
	it, ok, err = w.Next(ctx)
	if err != nil || !ok || it.Text != "after the secret" {
		t.Fatalf("Next = %+v, %v, %v", it, ok, err)
	}
	if cur, ok, _ := w.Current(); !ok || cur.Text != "after the secret" {
		t.Errorf("Current = %+v, %v", cur, ok)
	}
}

// TestWaylandStuckSource checks that a program that offers a text and never
// writes it cannot hold the connector's read.
func TestWaylandStuckSource(t *testing.T) {
	if os.Getenv("CBB_TEST_WAYLAND") == "" {
		t.Skip("set CBB_TEST_WAYLAND in a session with a data-control compositor and wl-clipboard")
	}
	logged := make(chan string, 8)
	w, err := OpenWayland(func(f string, a ...any) {
		select {
		case logged <- fmt.Sprintf(f, a...):
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// The stuck program: a second client whose source keeps the pipe open
	// and writes nothing.
	stuck, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer stuck.Close()
	var mu sync.Mutex
	var held []int
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, fd := range held {
			unix.Close(fd)
		}
	}()
	src := stuck.d.NewID(func(op uint16, a *wl.Args) error {
		if op == srcEvSend {
			_ = a.String()
			fd := a.FD()
			mu.Lock()
			held = append(held, fd)
			mu.Unlock()
		}
		return a.Err
	})
	stuck.d.Send(stuck.mgr, mgrCreateSource, (&wl.Request{}).Uint(src))
	stuck.d.Send(src, srcOffer, (&wl.Request{}).String("text/plain;charset=utf-8"))
	stuck.d.Send(stuck.device, devSetSelection, (&wl.Request{}).Uint(src))
	select {
	case msg := <-logged:
		if !strings.Contains(msg, "reading the clipboard") {
			t.Errorf("logged %q", msg)
		}
	case <-time.After(readTimeout + 3*time.Second):
		t.Fatal("the read of a stuck source never ended")
	}
}

func TestWaylandWrites(t *testing.T) {
	if os.Getenv("CBB_TEST_WAYLAND") == "" {
		t.Skip("set CBB_TEST_WAYLAND in a session with a data-control compositor and wl-clipboard")
	}
	// What the clipboard holds at open is known, but no change.
	if err := exec.Command("wl-copy", "there before").Run(); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if it, ok, _ := w.Current(); !ok || it.Text != "there before" {
		t.Errorf("Current = %+v, %v", it, ok)
	}
	select {
	case it := <-w.changes:
		t.Errorf("the clipboard at open came as a change: %+v", it)
	case <-time.After(300 * time.Millisecond):
	}
	paste := func(args ...string) string {
		out, _ := exec.Command("wl-paste", append([]string{"--no-newline"}, args...)...).Output()
		return string(out)
	}
	// Writes in quick succession replace each other's sources; each is
	// destroyed once, so the compositor sees no protocol error.
	for i := range 50 {
		if err := w.Write(fmt.Sprintf("write %d", i), false); err != nil {
			t.Fatal(err)
		}
	}
	if got := paste(); got != "write 49" {
		t.Errorf("wl-paste = %q", got)
	}
	select {
	case err := <-w.errc:
		t.Fatalf("the connection failed: %v", err)
	case it := <-w.changes:
		t.Fatalf("our own write came back as a change: %+v", it)
	case <-time.After(300 * time.Millisecond):
	}
	// An expired secret is given up only where it still is: a newer
	// selection made with the mouse stays.
	if err := w.Write("hunter2", true); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("wl-copy", "--primary", "selected by the user").Run(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := w.ClearIfUnchanged(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := paste("--primary"); got != "selected by the user" {
		t.Errorf("the primary selection is %q after giving up the secret", got)
	}
	if got := paste(); got == "hunter2" {
		t.Error("the secret is still in the clipboard")
	}
}
