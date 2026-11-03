// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
)

// TestKeyboardElsewhere: a Mac or a Windows PC says it cannot be one.
func TestKeyboardElsewhere(t *testing.T) {
	var h hub
	mac := startWith(t, &h, "mac", group.OSMacOS, nil)
	if _, err := mac.do(t, control.Header{Op: control.OpKeyboard, Name: "on"}, ""); err == nil || !strings.Contains(err.Error(), "only a Linux computer") {
		t.Errorf("keyboard on a Mac: %v", err)
	}
	if k := mac.status(t).Keyboard; k != nil {
		t.Errorf("a Mac's status has a keyboard: %+v", k)
	}
}
