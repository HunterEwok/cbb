// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"path/filepath"
	"testing"
)

// TestDefaultKey: the key is in systemd's state directory for the
// forwarder, else in cbb's.
func TestDefaultKey(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", "/var/lib/cbb-forward")
	if k := defaultKey(); k != filepath.Join("/var/lib/cbb-forward", "forwarder.pem") {
		t.Errorf("with STATE_DIRECTORY: %s", k)
	}
	t.Setenv("STATE_DIRECTORY", "")
	if k := defaultKey(); k != filepath.Join("/var/lib/cbb", "forwarder.pem") {
		t.Errorf("without: %s", k)
	}
}
