// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestLiteServiceFlags: the Rust service takes -state and -socket after the
// command, as launchd's plist, FreeBSD's rc script and OpenWrt's init script
// pass them to the Go service, and -user only as root.
func TestLiteServiceFlags(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "c.sock")
	cmd := exec.Command(bin, "service", "-state", filepath.Join(dir, "state"), "-socket", socket, "-no-mdns", "-no-listen")
	cmd.Stdout, cmd.Stderr = testWriter{t, "lite: ", nil}, testWriter{t, "lite: ", nil}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cmd.Process.Signal(os.Interrupt)
		<-done
	}()
	waitFor(t, "the control socket at -socket", func() bool {
		c, err := control.Dial(socket)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	if _, err := os.Stat(filepath.Join(dir, "state")); err != nil {
		t.Errorf("no state directory at -state: %v", err)
	}

	if os.Geteuid() != 0 {
		out, err := exec.Command(bin, "service", "-state", t.TempDir(), "-socket", filepath.Join(t.TempDir(), "c.sock"), "-user", "nobody").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "-user needs root") {
			t.Errorf("-user without root: %v\n%s", err, out)
		}
	}
}
