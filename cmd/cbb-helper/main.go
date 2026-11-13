// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command cbb-helper does for the service cbb what needs Go: it is started
// by cbb as its child and serves cbb's requests over its standard input and
// output (docs/design.md, "The service and its helper"). On Linux,
// cbb paste-helper uinput runs it as the uinput helper too (cbb-helper
// uinput), which needs Go's uinput keyboard. It logs to its standard error,
// which cbb passes on to its own log.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/helper"
	"github.com/HunterEwok/cbb/internal/peripheral"
	"github.com/HunterEwok/cbb/internal/testhooks"
	"github.com/HunterEwok/cbb/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, term.IsTerminal(int(os.Stdin.Fd()))))
}

func run(args []string, in io.Reader, out, errw io.Writer, terminal bool) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "-version" || args[0] == "--version") {
		fmt.Fprintln(out, version.String())
		if n := testhooks.Note(); n != "" {
			fmt.Fprintln(out, n)
		}
		return 0
	}
	if len(args) == 1 && args[0] == "uinput" {
		return runUinput(context.Background(), errw)
	}
	if len(args) > 0 || terminal {
		fmt.Fprintln(errw, "cbb-helper: the service cbb starts this program itself; run cbb instead")
		return 2
	}
	if n := testhooks.Note(); n != "" {
		fmt.Fprintln(errw, "cbb-helper:", n)
	}
	watchParent()
	err := newServer().Serve(in, out)
	// The keys it loaded leave the TPM with it.
	group.CloseTPM()
	if err != nil {
		fmt.Fprintln(errw, "cbb-helper:", err)
		return 1
	}
	return 0
}

// newServer is the helper with every operation this build serves.
func newServer() *helper.Server {
	// The service's tests stand in for an Apple TV's mDNS name, as they do
	// in their own process (peripheral.AppleTVName), when the helper runs
	// beside the Rust service.
	if name, ok := os.LookupEnv("CBB_TEST_APPLETV_NAME"); ok {
		peripheral.AppleTVName = func(context.Context, string) string { return name }
	}
	s := helper.New(version.String())
	s.HandleKeys()
	s.HandlePeripherals(os.Stderr)
	s.HandleAgent(os.Stderr)
	return s
}
