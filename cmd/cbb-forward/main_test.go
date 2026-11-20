// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/cbb/internal/version"
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

// TestVersion: cbb-forward says the version the release sets in it, as
// cbb-helper does; the release looks for its tag there.
func TestVersion(t *testing.T) {
	prev := version.Version
	version.Version = "v0.0.0-rc.1"
	t.Cleanup(func() { version.Version = prev })
	for _, arg := range []string{"version", "-version", "--version"} {
		var out, errw bytes.Buffer
		if code := run([]string{arg}, &out, &errw); code != 0 || !bytes.Contains(out.Bytes(), []byte("v0.0.0-rc.1")) {
			t.Errorf("%s: %d, %q, %q", arg, code, out.String(), errw.String())
		}
	}
}
