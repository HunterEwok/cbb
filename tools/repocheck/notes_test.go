// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
)

func TestCheckWorkNotes(t *testing.T) {
	note := "TO" + "DO"
	src := []byte("package a\n\n// " + note + ": later.\nvar todos = 1 // see roadmap item 37\n")
	got := checkWorkNotes("a.go", src)
	if len(got) != 1 || !strings.HasPrefix(got[0], "a.go:3: a "+note+" note") {
		t.Fatalf("checkWorkNotes = %q, want one problem on a.go:3", got)
	}
	if got := checkWorkNotes("internal/third_party/x/a.go", src); len(got) != 0 {
		t.Errorf("checkWorkNotes(third_party) = %q, want nothing", got)
	}
}
