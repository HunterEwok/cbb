// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

// Package consolepaste is the paste target on the Linux text console
// (design.md, "Remote paste"): cbb paste-helper console, which the
// cbb-console unit runs as root with CAP_SYS_ADMIN alone,
// puts the text into the input of the active virtual console with
// TIOCSTI, as if typed there. That works also where the kernel turns
// unprivileged TIOCSTI off (dev.tty.legacy_tiocsti = 0).
//
// It pastes only into a text console that a user logged in on, never into
// a login prompt, a graphical session's console or a locked one (vlock,
// physlock, logind's LockedHint).
package consolepaste

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/lockcheck"
)

// Console pastes into the active virtual console.
type Console struct {
	// For tests: the console's device, its name, and the logind session
	// on it; nil for the real ones.
	open    func(tty string) (*os.File, error)
	active  func() (string, error)
	session func(tty string) (string, error)
}

const kdGetMode = 0x4b3b // KDGETMODE; KD_TEXT is 0

// Target names the target (connector.Target).
func (c *Console) Target() string { return "console" }

// Inject types text into the active virtual console, with a carriage
// return for each line break and for Enter (connector.Target). Both
// methods type: a console has no clipboard to paste from.
func (c *Console) Inject(ctx context.Context, text, method string, enter, secret bool) error {
	if method != "paste" && method != "type" {
		return &connector.Refusal{Reason: fmt.Sprintf("the console pastes or types, not %q", method)}
	}
	tty, err := c.activeTTY()
	if err != nil {
		return err
	}
	if why := c.locked(tty, connector.NoLockCheck(ctx)); why != "" {
		return &connector.Refusal{Reason: why}
	}
	f, err := c.openTTY(tty)
	if err != nil {
		return err
	}
	defer f.Close()
	if c.open == nil {
		mode, err := unix.IoctlGetInt(int(f.Fd()), kdGetMode)
		if err != nil {
			return fmt.Errorf("reading the mode of %s: %w", tty, err)
		}
		if mode != 0 {
			return &connector.Refusal{Reason: "the active console shows a graphical session"}
		}
	}
	in := strings.ReplaceAll(text, "\n", "\r")
	if enter {
		in += "\r"
	}
	for i := range len(in) {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := in[i]
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TIOCSTI, uintptr(unsafe.Pointer(&b))); errno != 0 {
			return fmt.Errorf("typing into %s: %w", tty, errno)
		}
	}
	return nil
}

// activeTTY returns the name of the active virtual console, such as tty2.
func (c *Console) activeTTY() (string, error) {
	if c.active != nil {
		return c.active()
	}
	b, err := os.ReadFile("/sys/class/tty/tty0/active")
	if err != nil {
		return "", &connector.Refusal{Reason: "this computer has no virtual console"}
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Console) openTTY(tty string) (*os.File, error) {
	if c.open != nil {
		return c.open(tty)
	}
	return os.OpenFile("/dev/"+tty, os.O_WRONLY|unix.O_NOCTTY, 0)
}

// locked says why the console takes no text now, or "" if it does: no one
// is logged in on it, or it is locked, or logind does not tell whether it
// is, unless noLockCheck lets the paste go on then.
func (c *Console) locked(tty string, noLockCheck bool) string {
	if name := lockcheck.Locker(true); name != "" {
		return "the console is locked (" + name + " runs)"
	}
	id, err := c.sessionOn(tty)
	switch {
	case err != nil:
		return "cannot tell who is logged in on the console: " + err.Error()
	case id == "":
		return "no one is logged in on the active console"
	case c.session != nil:
		return ""
	}
	switch locked, known := lockcheck.State(id); {
	case locked:
		return "the console's session is locked"
	case !known && !noLockCheck:
		return lockcheck.Unknown
	}
	return ""
}

// sessionOn returns logind's active text session on tty, or "".
func (c *Console) sessionOn(tty string) (string, error) {
	if c.session != nil {
		return c.session(tty)
	}
	ids, err := lockcheck.Sessions()
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		p := lockcheck.Show(id, "TTY", "Type", "Active")
		if p["TTY"] == tty && p["Type"] == "tty" && p["Active"] == "yes" {
			return id, nil
		}
	}
	return "", nil
}
