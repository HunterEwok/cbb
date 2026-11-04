// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/release"
	"rsc.io/qr"
)

func TestWriteQR(t *testing.T) {
	const url = "http://192.168.1.20:8766/"
	var b bytes.Buffer
	if err := writeQR(&b, url); err != nil {
		t.Fatal(err)
	}
	code, _ := qr.Encode(url, qr.M)
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	// Two modules per line, a quiet zone of two on each side.
	if want := (code.Size + 4 + 1) / 2; len(lines) != want {
		t.Errorf("%d lines, want %d", len(lines), want)
	}
	// Read the modules back from the colors and compare.
	for i, line := range lines {
		cells := strings.Split(line, "\x1b[")[1:]
		cells = cells[:len(cells)-1] // the reset
		if len(cells) != code.Size+4 {
			t.Fatalf("line %d has %d cells", i, len(cells))
		}
		for x, cell := range cells {
			for half, y := range []int{2 * i, 2*i + 1} {
				mx, my := x-2, y-2
				want := mx >= 0 && my >= 0 && mx < code.Size && my < code.Size && code.Black(mx, my)
				color := strings.Split(strings.TrimSuffix(cell, "m▀"), ";")[half]
				if got := color == "30" || color == "40"; got != want {
					t.Fatalf("module %d,%d: black %v, want %v", mx, my, got, want)
				}
			}
		}
	}
}

func TestEntriesString(t *testing.T) {
	set := node.EntriesSet{Keys: release.File{Body: []byte(`{"a":1}`)}, Entries: release.File{Body: []byte(`{"b":2}`)}}
	s, err := entriesString(set)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseEntries("  " + s + "\n")
	if err != nil || string(got.Keys.Body) != `{"a":1}` || string(got.Entries.Body) != `{"b":2}` {
		t.Fatalf("got %+v: %v", got, err)
	}
	for _, bad := range []string{"", "entries:" + s, entriesPrefix + "!!", entriesPrefix + "e30x"} {
		if _, err := parseEntries(bad); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}
