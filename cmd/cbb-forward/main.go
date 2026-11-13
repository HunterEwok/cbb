// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command cbb-forward runs a forwarder (docs/design.md, "The forwarder")
// as a service of its own: cbb forward starts it in its place, and its systemd
// unit runs it under a user of its own, apart from cbb and the keys of
// cbb-helper.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is cbb-forward with args: its version, as cbb-helper's, which the
// release sets and checks, or the forwarder.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "-version" || args[0] == "--version") {
		fmt.Fprintln(stdout, version.String())
		return 0
	}
	return forward.Command(args, stdout, stderr, defaultKey())
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
