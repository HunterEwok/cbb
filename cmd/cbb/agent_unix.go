// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/desktop"
)

// runDesktop is the agent on a Linux desktop: it opens the session's
// clipboard through Wayland or X11, and opens it again when the display
// connection drops.
func runDesktop(ctx context.Context, logf func(string, ...any), stderr io.Writer) int {
	if !lockAgent() {
		logf("cbb: another agent links this session's clipboard already")
		return 0
	}
	backoff := time.Second
	failures := 0
	for ctx.Err() == nil {
		b, how, err := desktop.Open(logf)
		if err != nil {
			// The session is gone, or not there yet: try a few times, then
			// give up, so a connector does not outlive its session.
			if failures++; failures > 10 {
				return fail(stderr, err)
			}
		} else {
			failures, backoff = 0, time.Second
			logf("cbb: linked the clipboard through %s", how)
			err = connector.Run(ctx, connector.Config{Socket: control.SocketPath(), Board: b, Commands: true, Files: receivedFiles(), Logf: logf})
			b.Close()
			if err == nil || !errors.Is(err, connector.ErrBoardGone) {
				return 0
			}
			logf("cbb: %v; opening the display again", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
	return 0
}

// lockAgent reports whether this is the user's only agent: the user unit
// and the autostart entry may both start one. The lock lasts as long as
// the process; without a runtime directory, running twice beats not
// running.
func lockAgent() bool {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return true
	}
	f, err := os.OpenFile(filepath.Join(dir, "cbb-agent.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return true
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return !errors.Is(err, syscall.EWOULDBLOCK)
	}
	agentLockFile = f // kept open, and so locked, until the process ends
	return true
}

var agentLockFile *os.File
