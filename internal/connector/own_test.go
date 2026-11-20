// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/control"
)

// The session runs a command the service names only when its own user
// set it: one the service made up is refused and never runs.
func TestActedRunsOnlyTheUsersOwnCommand(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	mark := filepath.Join(t.TempDir(), "ran")
	command := []string{"/usr/bin/touch", mark}
	m := &control.Message{Header: control.Header{Op: control.OpAct, Name: "backup", Command: command}}
	logf := func(string, ...any) {}

	ans := acted(context.Background(), nil, m, logf)
	if !ans.Refused || !strings.Contains(ans.Error, "only the commands its user set") {
		t.Fatalf("a command the user did not set: %+v", ans.Header)
	}
	if _, err := os.Stat(mark); err == nil {
		t.Fatal("the command ran")
	}

	dir := filepath.Join(cfg, "cbb")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, actions.OwnFile), []byte(`{"backup":["/usr/bin/touch","`+mark+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ans := acted(context.Background(), nil, m, logf); ans.Error != "" {
		t.Fatalf("the user's own command: %+v", ans.Header)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("the command did not run: %v", err)
	}
}
