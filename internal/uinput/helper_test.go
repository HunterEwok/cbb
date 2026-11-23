// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package uinput

import (
	"os"
	"testing"
)

// TestNoSessionNoService: without a graphical session on the computer's
// screen (CI's case), or with no paste the service handed, the keys are
// refused, and the refusal says why.
func TestNoSessionNoService(t *testing.T) {
	if os.Getenv("XDG_SESSION_TYPE") == "" {
		if why := Allowed(uint32(os.Getuid())); why == "" {
			t.Error("allowed with no session on the screen")
		}
	}
	if why := AskService(uint32(os.Getuid()), "paste", "no-such-grant"); why == "" {
		t.Error("allowed with no paste handed")
	}
}
