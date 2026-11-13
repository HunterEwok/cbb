// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"testing"

	"github.com/HunterEwok/cbb/internal/version"
)

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
