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

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/uinput"
)

// runUinput is the keys helper, which the cbb-uinput unit runs as root
// through cbb paste-helper uinput: it holds a uinput keyboard and presses a
// remote paste's keys for the user of the active graphical session
// (internal/uinput).
func runUinput(ctx context.Context, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "cbb:", err)
		return 1
	}
	if os.Geteuid() != 0 {
		return fail(errors.New("the uinput helper runs as root, from the cbb-uinput unit"))
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	kbd, err := uinput.Open(uinput.Device, "CBB remote paste")
	if err != nil {
		return fail(fmt.Errorf("%w (is the uinput module loaded?)", err))
	}
	defer kbd.Close()
	// The desktop connectors reach the helper as they reach the service:
	// through the group of the service's control socket.
	fi, err := os.Stat(control.SocketPath())
	if err != nil {
		return fail(fmt.Errorf("the service's control socket: %w (is cbb running?)", err))
	}
	gid := int(fi.Sys().(*syscall.Stat_t).Gid)
	if err := os.MkdirAll(filepath.Dir(uinput.Socket), 0o755); err != nil {
		return fail(err)
	}
	os.Remove(uinput.Socket)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: uinput.Socket, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	defer os.Remove(uinput.Socket)
	// The helper presses the keys only for a remote paste that the service
	// handed to the session on the screen, by the caller's credentials and
	// the service's grant.
	if err := os.Chown(uinput.Socket, 0, gid); err != nil {
		return fail(err)
	}
	if err := os.Chmod(uinput.Socket, 0o660); err != nil {
		return fail(err)
	}
	logf("cbb: pressing the keys of remote pastes for the active session, at %s", uinput.Socket)
	h := &uinput.Helper{Keys: kbd, Logf: logf}
	if err := h.Serve(ctx, ln); err != nil {
		return fail(err)
	}
	return 0
}
