// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLockAgent allows one agent in a user's session: the user unit and the
// autostart entry may both start one.
func TestLockAgent(t *testing.T) {
	if os.Getenv("CBB_LOCK_CHILD") == "1" {
		if lockAgent() {
			os.Exit(0)
		}
		os.Exit(3)
	}
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if !lockAgent() {
		t.Fatal("the first agent did not get the lock")
	}
	defer func() { agentLockFile.Close(); agentLockFile = nil }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockAgent$")
	cmd.Env = append(os.Environ(), "CBB_LOCK_CHILD=1")
	if err := cmd.Run(); err == nil {
		t.Error("a second agent got the lock too")
	} else if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 3 {
		t.Errorf("the second agent: %v", err)
	}
}

// TestRunEnds: the agent ends with its context, and stays out of a
// session another agent links already.
func TestRunEnds(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	if err := Run(ctx, "/nonexistent", logf); err != nil {
		t.Fatal(err)
	}
	defer func() { agentLockFile.Close(); agentLockFile = nil }()
	if err := runDesktop(context.Background(), "/nonexistent", logf); err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "another agent") {
		t.Errorf("logged %q", logs)
	}
	if dir := ReceivedFiles(); dir != "" && filepath.Base(dir) != "received" {
		t.Errorf("received files in %s", dir)
	}
}
