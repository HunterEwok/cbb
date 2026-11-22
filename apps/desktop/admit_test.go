// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestOpenWindow: OpenWindow runs cbb pair -app with the app's own file as
// the administrator, -admin for an admin phone; WindowState shows the
// digits and the QR code cbb writes there, and the device that failed and
// the one that joined; CloseWindow removes the file, which cbb takes as
// closing the window.
func TestOpenWindow(t *testing.T) {
	d := &Desk{tr: map[string]string{}, socket: filepath.Join(t.TempDir(), "none.sock")}
	ran := make(chan []string, 4)
	steps := make(chan string)
	written := make(chan struct{})
	old := adminRun
	adminRun = func(a []string, _ string, _ bool) error {
		ran <- a
		for line := range steps {
			if line == "" {
				break
			}
			if line == "exit" {
				return nil
			}
			if err := os.WriteFile(a[2], []byte(line+"\n"), 0o600); err != nil {
				return err
			}
			written <- struct{}{}
		}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(a[2]); err != nil {
				return &adminError{msg: "cancelled"}
			}
		}
		return nil
	}
	defer func() { adminRun = old }()
	if w := d.WindowState(); w.Running {
		t.Fatalf("a window before any: %+v", w)
	}

	ended := make(chan struct{})
	go func() { d.OpenWindow(true); close(ended) }()
	a := <-ran
	if len(a) != 4 || !slices.Equal([]string{a[0], a[1], a[3]}, []string{"pair", "-app", "-admin"}) {
		t.Fatalf("ran %q", a)
	}
	if w := d.WindowState(); !w.Running || w.Code != "" {
		t.Errorf("before cbb wrote: %+v", w)
	}
	steps <- `{"code":"654321","qr":"cbb://pair?c=654321","address":"192.168.1.5:8764","expires":300}`
	<-written
	w := d.WindowState()
	if w.Code != "654 321" || !strings.HasPrefix(w.Image, "data:image/png;base64,") || w.Address != "192.168.1.5:8764" {
		t.Errorf("the window: %+v", w)
	}
	if left := time.Until(time.UnixMilli(w.Ends)); left < 4*time.Minute || left > 5*time.Minute {
		t.Errorf("it ends in %v", left)
	}
	steps <- `{"code":"654321","qr":"cbb://pair?c=654321","expires":300,"refused":"the code did not match"}`
	<-written
	if w := d.WindowState(); w.Refused != "the code did not match" {
		t.Errorf("after a failed device: %+v", w)
	}
	steps <- ""
	d.CloseWindow()
	<-ended
	if d.message != "" {
		t.Errorf("a closed window said %q", d.message)
	}

	// A device that joins: the window says so.
	ended = make(chan struct{})
	go func() { d.OpenWindow(false); close(ended) }()
	if a := <-ran; len(a) != 3 {
		t.Fatalf("ran %q", a)
	}
	steps <- `{"code":"654321","qr":"cbb://pair?c=654321","expires":300,"done":true,"name":"laptop"}`
	<-written
	if w := d.WindowState(); w.Joined != "laptop" {
		t.Errorf("after the join: %+v", w)
	}
	steps <- "exit"
	<-ended
	if d.message != "It joined the group." {
		t.Errorf("a join said %q", d.message)
	}
}
