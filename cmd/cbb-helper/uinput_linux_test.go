// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"strings"
	"testing"
)

// The uinput helper runs only as root, with the uinput module loaded and
// the service's control socket there; without them it says which is
// missing and ends with 1, pressing nothing.
func TestUinputHelperSaysWhatIsMissing(t *testing.T) {
	var out, errw bytes.Buffer
	code := run([]string{"uinput"}, nil, &out, &errw, false)
	if code != 1 {
		t.Fatalf("cbb-helper uinput without what it needs: code %d, %q", code, errw.String())
	}
	msg := errw.String()
	if !strings.Contains(msg, "runs as root") && !strings.Contains(msg, "uinput module") && !strings.Contains(msg, "control socket") {
		t.Errorf("the reason: %q", msg)
	}
}
