// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package agent links a user session's clipboard with the service: on a
// Linux or FreeBSD desktop through Wayland or X11, on a Mac and on Windows
// through the system's pasteboard, where it is also the remote paste
// target (Windows) and runs the quick actions of the session. The Go
// command cbb agent runs it, and so does cbb-helper for the Rust cbb agent
// (docs/design.md, "The service and its helper").
package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/pasteboard"
)

// Run links this session's clipboard with the service at socket until ctx
// ends or the service goes. It returns at once, with no error, when
// another agent links this session already.
func Run(ctx context.Context, socket string, logf func(string, ...any)) error {
	switch runtime.GOOS {
	case "linux", "freebsd":
		return runDesktop(ctx, socket, logf)
	case "darwin", "windows":
	default:
		return fmt.Errorf("the agent has no clipboard to link on %s", runtime.GOOS)
	}
	if !first() {
		logf("cbb: another agent links this session's clipboard already")
		return nil
	}
	if err := letServiceQuery(); err != nil {
		logf("cbb: the service may not see who runs this agent, so it gets no remote pastes or quick actions: %v", err)
	}
	b := pasteboard.General()
	if _, _, err := b.Read(); errors.Is(err, pasteboard.ErrUnsupported) {
		return err
	}
	w := pasteboard.NewWatch(b)
	return connector.Run(ctx, connector.Config{Socket: socket, Board: w, Target: target(w), Actor: actions.Session(), Commands: true, Files: ReceivedFiles(), Logf: logf})
}

// ReceivedFiles is the folder where the agent keeps the files the group
// copies, a folder for each copy, in the user's cache: ~/.cache on Linux,
// ~/Library/Caches on a Mac, %LocalAppData% on Windows. "" takes no files.
func ReceivedFiles() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "cbb", "received")
}
