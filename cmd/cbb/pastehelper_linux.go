// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/consolepaste"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/uinput"
)

// runConsoleHelper is the helper for the text console, run by the
// cbb-console unit as root; it logs to the journal.
func runConsoleHelper(ctx context.Context, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		return fail(stderr, errors.New("the console helper runs as root, from the cbb-console unit"))
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	logf("cbb: pasting into the active text console")
	if err := connector.Run(ctx, connector.Config{Socket: control.SocketPath(), Target: &consolepaste.Console{}, Logf: logf}); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// runUinputHelper is the keys helper, run by the cbb-uinput
// unit as root: it holds a uinput keyboard and presses a paste's keys for
// the user of the active graphical session (internal/uinput).
func runUinputHelper(ctx context.Context, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		return fail(stderr, errors.New("the uinput helper runs as root, from the cbb-uinput unit"))
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	kbd, err := uinput.Open(uinput.Device, "CBB remote paste")
	if err != nil {
		return fail(stderr, fmt.Errorf("%w (is the uinput module loaded?)", err))
	}
	defer kbd.Close()
	// The desktop connectors reach the helper as they reach the service:
	// through the group of the service's control socket.
	fi, err := os.Stat(control.SocketPath())
	if err != nil {
		return fail(stderr, fmt.Errorf("the service's control socket: %w (is cbb running?)", err))
	}
	gid := int(fi.Sys().(*syscall.Stat_t).Gid)
	if err := os.MkdirAll(filepath.Dir(uinput.Socket), 0o755); err != nil {
		return fail(stderr, err)
	}
	os.Remove(uinput.Socket)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: uinput.Socket, Net: "unix"})
	if err != nil {
		return fail(stderr, err)
	}
	defer os.Remove(uinput.Socket)
	// The helper presses the keys only for a remote paste that the service
	// handed to the session on the screen, by the caller's credentials and
	// the service's grant.
	if err := os.Chown(uinput.Socket, 0, gid); err != nil {
		return fail(stderr, err)
	}
	if err := os.Chmod(uinput.Socket, 0o660); err != nil {
		return fail(stderr, err)
	}
	logf("cbb: pressing the keys of remote pastes for the active session, at %s", uinput.Socket)
	h := &uinput.Helper{Keys: kbd, Logf: logf}
	if err := h.Serve(ctx, ln); err != nil {
		return fail(stderr, err)
	}
	return 0
}
