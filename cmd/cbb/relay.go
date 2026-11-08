// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/relay"
)

// cmdRelay runs a blind relay (relay.Command).
func cmdRelay(args []string, stdout, stderr io.Writer) int {
	return relay.Command(args, stdout, stderr, defaultRelayKey())
}

// defaultRelayKey is where the relay keeps its keys: in systemd's state
// directory for it, or next to the service's state.
func defaultRelayKey() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return filepath.Join(d, "relay.pem")
	}
	return filepath.Join(defaultStateDir(), "relay.pem")
}
