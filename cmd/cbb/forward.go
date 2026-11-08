// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/forward"
)

// cmdForward runs a forwarder (forward.Command).
func cmdForward(args []string, stdout, stderr io.Writer) int {
	return forward.Command(args, stdout, stderr, defaultForwarderKey())
}

// defaultForwarderKey is where the forwarder keeps its key: in systemd's
// state directory for it, or next to the service's state.
func defaultForwarderKey() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return filepath.Join(d, "forwarder.pem")
	}
	return filepath.Join(defaultStateDir(), "forwarder.pem")
}
