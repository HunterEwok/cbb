// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestPreviousRelease holds the promise that from 0.6 on a device of
// version N works in one group with a device of N-1: the previous release's cbb (CBB_PREVIOUS, which
// tools/e2e/previous.sh downloads) and this build's (CBB_LITE) join one
// group, the previous one also dialing this build directly, sync both
// ways and take the record of a device admitted after them, and the
// previous one takes its own removal. The previous release is driven only through its own command
// line, which may differ from this build's.
func TestPreviousRelease(t *testing.T) {
	prev, cur := os.Getenv("CBB_PREVIOUS"), os.Getenv("CBB_LITE")
	if prev == "" || cur == "" {
		t.Skip("CBB_PREVIOUS and CBB_LITE are not both set: tools/e2e/previous.sh finds no release of 0.6 or later before this one")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	var h hub
	root := startService(t, &h, "root")
	join := func(bin, name string) string {
		t.Helper()
		c, code := openWindow(t, root)
		defer c.Close()
		dir := t.TempDir()
		cmd := exec.Command(bin, "-state", dir, "pair", "-name", name, "-code", root.addr())
		cmd.Stdin = strings.NewReader(code + "\n")
		cmd.Stderr = testWriter{t, name + " join: ", nil}
		if out, err := cmd.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
			t.Fatalf("cbb pair on %s: %v; %s", name, err, out)
		}
		if m, err := c.Receive(); err != nil || m.Name != name {
			t.Fatalf("pair on the root ended with %+v, %v for %s", m, err, name)
		}
		return dir
	}
	curDir := join(cur, "current")
	prevDir := join(prev, "previous")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	curAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	current := startLite(t, cur, curDir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", root.addr())
	previous := startLite(t, prev, prevDir, "-no-mdns", "-no-listen", "-peer", root.addr(), "-peer", curAddr)
	cli := func(bin string, s *testService, stdin string, args ...string) string {
		t.Helper()
		out, err := runCLI(bin, s.socket, stdin, args...)
		if err != nil {
			t.Fatalf("cbb %s: %v; %s", strings.Join(args, " "), err, out)
		}
		return out
	}
	for _, s := range []struct {
		bin string
		s   *testService
	}{{cur, current}, {prev, previous}} {
		cli(s.bin, s.s, "", "sync", "on")
	}

	cli(prev, previous, "from the previous release", "copy")
	waitFor(t, "the root and this build have the previous release's copy", func() bool {
		return root.paste(t) == "from the previous release" && current.paste(t) == "from the previous release"
	})
	cli(cur, current, "from this build", "copy")
	waitFor(t, "the previous release has this build's copy", func() bool {
		out, err := runCLI(prev, previous.socket, "", "paste")
		return err == nil && out == "from this build"
	})

	// A device admitted after both: the previous release takes its record
	// and its copy.
	late := startService(t, &h, "late")
	pairWith(t, root, late)
	if _, err := late.do(t, control.Header{Op: control.OpCopy}, "from a device admitted later"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the previous release has the later device's copy", func() bool {
		out, err := runCLI(prev, previous.socket, "", "paste")
		return err == nil && out == "from a device admitted later"
	})

	// Its removal reaches it.
	if _, err := root.do(t, control.Header{Op: control.OpRemove, Device: "previous"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the previous release takes its removal", func() bool {
		out, _ := runCLI(prev, previous.socket, "", "status")
		return strings.Contains(out, "removed")
	})
}
