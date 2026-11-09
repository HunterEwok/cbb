// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"io"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
)

// TestKeyboardElsewhere: on a Mac or a Windows PC the Rust service's
// keyboard request says it cannot be one.
func TestKeyboardElsewhere(t *testing.T) {
	s := New("test")
	s.HandlePeripherals(io.Discard)
	for i, os := range []string{group.OSMacOS, group.OSWindows} {
		seq := uint64(i + 1)
		got := exchange(t, s, request(t, OpKeyboard, seq, PeripheralRequest{Dir: t.TempDir(), Name: "mac", OS: os,
			Header: control.Header{Op: control.OpKeyboard, Name: "on"}}))
		if ans := got[seq]; ans == nil || !strings.Contains(ans.Error, "only a Linux computer") {
			t.Errorf("keyboard on %s: %+v", os, ans)
		}
	}
}
