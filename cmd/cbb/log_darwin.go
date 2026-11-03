// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The labels of the launchd jobs in packaging/macos, which launchd puts in
// XPC_SERVICE_NAME for the programs it starts.
const (
	serviceLabel = "tools.cbb"
	agentLabel   = serviceLabel + ".agent"
)

// serviceLog returns where the service logs: started by launchd, its own
// log in /Library/Logs/cbb, moved to service.log.1 past 1 MiB as
// on Windows; standard error follows the log, so that a crash lands in it
// too. Started by hand, standard error.
func serviceLog(stderr io.Writer) (io.Writer, func()) {
	if os.Getenv("XPC_SERVICE_NAME") != serviceLabel {
		return stderr, func() {}
	}
	l, err := openLogThen("/Library/Logs/cbb/service.log", toStderr)
	if err != nil {
		fmt.Fprintln(stderr, "cbb: the log:", err)
		return stderr, func() {}
	}
	return l, func() { l.Close() }
}

// agentLog returns where the agent logs: started by launchd, which has no
// file for it, ~/Library/Logs/cbb/agent.log, moved to
// agent.log.1 past 1 MiB; started by hand, standard error.
func agentLog(stderr io.Writer) (io.Writer, func(), error) {
	if os.Getenv("XPC_SERVICE_NAME") != agentLabel {
		return stderr, func() {}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return stderr, func() {}, err
	}
	l, err := openLogThen(filepath.Join(home, "Library", "Logs", "cbb", "agent.log"), toStderr)
	if err != nil {
		return stderr, func() {}, err
	}
	return l, func() { l.Close() }, nil
}

// toStderr makes the log's file the process's standard error, where the
// runtime writes a panic.
func toStderr(f *os.File) { unix.Dup2(int(f.Fd()), 2) }
