// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package rootless

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirs(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "relative")
	t.Setenv("XDG_DATA_HOME", "/data")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	for got, want := range map[string]string{
		StateDir():  "/home/u/.local/state/cbb",
		UpdateDir(): "/home/u/.local/state/cbb-update",
		ConfigDir(): "/home/u/.config/cbb",
		ShareDir():  "/data/cbb",
		UnitDir():   "/home/u/.config/systemd/user",
		Socket():    "/run/user/1000/cbb/control.sock",
	} {
		if got != filepath.Clean(want) {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

// A home whose ~/.local is a link still has its rootless install found.
func TestSameFileThroughLinks(t *testing.T) {
	d := t.TempDir()
	real := filepath.Join(d, "real")
	if err := os.MkdirAll(filepath.Join(real, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(real, "bin", "cbb")
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(d, ".local")); err != nil {
		t.Fatal(err)
	}
	if !sameFile(exe, filepath.Join(d, Bin)) {
		t.Error("a linked ~/.local was not taken for the install")
	}
	if sameFile(exe, filepath.Join(d, "other")) {
		t.Error("another path was taken for the install")
	}
}
