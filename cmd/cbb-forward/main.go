// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command cbb-forward runs a forwarder (docs/design.md, "The forwarder")
// as a service of its own: cbb forward starts it in its place, and its systemd
// unit runs it under a user of its own, apart from cbb and the keys of
// cbb-helper.
package main

import (
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/forward"
)

func main() {
	os.Exit(forward.Command(os.Args[1:], os.Stdout, os.Stderr, defaultKey()))
}

// defaultKey is in systemd's state directory for it, or in cbb's own state
// directory; cbb forward names cbb's with -key.
func defaultKey() string {
	dir := os.Getenv("STATE_DIRECTORY")
	if dir == "" {
		dir = "/var/lib/cbb"
	}
	return filepath.Join(dir, "forwarder.pem")
}
