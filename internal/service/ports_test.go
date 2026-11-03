// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPorts(t *testing.T) {
	dir := t.TempDir()
	old := EnvFile
	t.Cleanup(func() { EnvFile = old })
	EnvFile = filepath.Join(dir, "missing.env")

	// Nothing set: the defaults.
	if p, err := Port(); err != nil || p != MemberPort {
		t.Errorf("default: %d %v", p, err)
	}
	// The file, as install.sh writes it; the last line wins.
	EnvFile = filepath.Join(dir, "cbb.env")
	os.WriteFile(EnvFile, []byte("# written by install.sh\nCBB_PORT=9000\nOTHER=1\nCBB_PORT=\"9100\"\n"), 0o644)
	if p, err := Port(); err != nil || p != 9100 {
		t.Errorf("from the file: %d %v", p, err)
	}
	// The environment wins over the file, as systemd sets it.
	t.Setenv("CBB_PORT", "9200")
	if p, err := Port(); err != nil || p != 9200 {
		t.Errorf("from the environment: %d %v", p, err)
	}
	for _, bad := range []string{"80", "65536", "port", "-1"} {
		t.Setenv("CBB_PORT", bad)
		if _, err := Port(); err == nil || !strings.Contains(err.Error(), "CBB_PORT") {
			t.Errorf("CBB_PORT=%s: %v", bad, err)
		}
	}
}

func TestHomeCGNAT(t *testing.T) {
	dir := t.TempDir()
	old := EnvFile
	t.Cleanup(func() { EnvFile = old })
	EnvFile = filepath.Join(dir, "missing.env")
	if on, err := HomeCGNAT(); err != nil || on {
		t.Errorf("default: %v %v", on, err)
	}
	EnvFile = filepath.Join(dir, "cbb.env")
	os.WriteFile(EnvFile, []byte("CBB_PORT=9000\nCBB_HOME_CGNAT=1\n"), 0o644)
	if on, err := HomeCGNAT(); err != nil || !on {
		t.Errorf("from the file: %v %v", on, err)
	}
	t.Setenv("CBB_HOME_CGNAT", "0")
	if on, err := HomeCGNAT(); err != nil || on {
		t.Errorf("from the environment: %v %v", on, err)
	}
	t.Setenv("CBB_HOME_CGNAT", "yes")
	if _, err := HomeCGNAT(); err == nil || !strings.Contains(err.Error(), "CBB_HOME_CGNAT") {
		t.Errorf("CBB_HOME_CGNAT=yes: %v", err)
	}
}
