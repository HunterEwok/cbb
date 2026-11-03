// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package consolepaste

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/cbb/internal/connector"
)

// openPTY returns the two ends of a new pseudo-terminal.
func openPTY(t *testing.T) (ptmx, pts *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals: %v", err)
	}
	t.Cleanup(func() { ptmx.Close() })
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	pts, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pts.Close() })
	return ptmx, pts
}

// TestConsole types into a pseudo-terminal in place of the console; TIOCSTI
// on a terminal that is not its own needs CAP_SYS_ADMIN, so it runs as root.
func TestConsole(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("TIOCSTI into another terminal needs root")
	}
	_, pts := openPTY(t)
	session := "c1"
	c := &Console{
		open: func(tty string) (*os.File, error) {
			if tty != "tty3" {
				t.Errorf("opened %s", tty)
			}
			return os.OpenFile(pts.Name(), os.O_WRONLY|unix.O_NOCTTY, 0)
		},
		active:  func() (string, error) { return "tty3", nil },
		session: func(string) (string, error) { return session, nil },
	}
	if c.Target() != "console" {
		t.Errorf("Target = %q", c.Target())
	}
	ctx := context.Background()
	if err := c.Inject(ctx, "ls -l\nécho \"$HOME\"", "type", true, false); err != nil {
		if errors.Is(err, unix.EIO) || errors.Is(err, unix.EPERM) {
			t.Skipf("TIOCSTI is not allowed here: %v", err)
		}
		t.Fatal(err)
	}
	read := func() string {
		pts.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, err := pts.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf[:n])
	}
	if got := read(); got != "ls -l\n" {
		t.Errorf("first line %q", got)
	}
	if got := read(); got != "écho \"$HOME\"\n" {
		t.Errorf("second line %q", got)
	}

	session = ""
	var r *connector.Refusal
	if err := c.Inject(ctx, "at the login prompt", "type", false, false); !errors.As(err, &r) {
		t.Errorf("with no one logged in: %v", err)
	}
}
