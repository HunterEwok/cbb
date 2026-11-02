// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

func TestLeaveVersion1Group(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}

	// No records, or records of version 2: nothing moves.
	if left, err := leaveVersion1Group(dir); left || err != nil {
		t.Fatalf("no records: %v %v", left, err)
	}
	write(group.FileName, "{}")
	write(group.RecordsFileName, `{"v":2,"records":[]}`)
	if left, err := leaveVersion1Group(dir); left || err != nil || !exists(filepath.Join(dir, group.FileName)) {
		t.Fatalf("records of version 2: %v %v", left, err)
	}

	// A group of 0.5: its files move, the settings stay.
	write(group.RecordsFileName, "\n [ ]")
	write(group.CredentialsFileName, "{}")
	write(modeFile, "own")
	left, err := leaveVersion1Group(dir)
	if !left || err != nil {
		t.Fatalf("a group of 0.5: %v %v", left, err)
	}
	for _, name := range []string{group.FileName, group.RecordsFileName, group.CredentialsFileName} {
		if exists(filepath.Join(dir, name)) || !exists(filepath.Join(dir, oldGroupDir, name)) {
			t.Errorf("%s did not move", name)
		}
	}
	if !exists(filepath.Join(dir, modeFile)) {
		t.Error("the sync mode moved")
	}
	if _, err := group.Load(dir); err != group.ErrNoGroup {
		t.Errorf("the device is still in a group: %v", err)
	}
	if left, err := leaveVersion1Group(dir); left || err != nil {
		t.Fatalf("again: %v %v", left, err)
	}
}
