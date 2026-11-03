// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/HunterEwok/cbb/internal/openwrt"
	"github.com/HunterEwok/cbb/internal/rootless"
)

// runService runs the service until a signal stops it; systemd keeps its
// output, and on a Mac its own log does (serviceLog).
func runService(stderr io.Writer, run func(context.Context, func(string, ...any)) error) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stderr, closeLog := serviceLog(stderr)
	defer closeLog()
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	if err := run(ctx, logf); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// firstAgent reports that no other agent runs; launchd starts only one.
func firstAgent() bool { return true }

func defaultStateDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" { // set by systemd
		return d
	}
	switch {
	case rootless.Is():
		return rootless.StateDir()
	case runtime.GOOS == "darwin":
		return "/Library/Application Support/cbb/state"
	case runtime.GOOS == "freebsd":
		return "/var/db/cbb"
	case openwrt.Is():
		// /var is in RAM there; sysupgrade keeps /etc.
		return "/etc/cbb/state"
	}
	return "/var/lib/cbb"
}
