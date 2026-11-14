// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import "fmt"

// The bounds this check reads by, written here apart from the core and
// compared with the core's registry (bounds.json), so that neither moves
// without the other.
const (
	maxSig2      = 8192
	maxSig2Head  = 32 * 1024
	maxMedia     = 1 << 30
	maxInt       = 1<<63 - 1
	maxPasteText = 1 << 20
	maxTypedText = 16384
)

func checkBounds(dir string) {
	var v struct {
		Bounds []struct {
			Name  string
			Value uint64
		}
	}
	load(dir, "bounds.json", &v)
	reg := map[string]uint64{}
	for _, b := range v.Bounds {
		reg[b.Name] = b.Value
	}
	ours := map[string]uint64{
		"format::envelope::MAX_SIG2":       maxSig2,
		"format::envelope::MAX_SIG2_HEAD":  maxSig2Head,
		"format::copy::MIN_WRAP":           minWrap,
		"media::MAX_MEDIA":                 maxMedia,
		"format::cbor::MAX_INT":            maxInt,
		"commands::orders::MAX_PASTE_TEXT": maxPasteText,
		"commands::orders::MAX_TYPED_TEXT": maxTypedText,
	}
	for name, n := range ours {
		got, ok := reg[name]
		if !ok || got != n {
			fail("bounds: %s is %d here and %d (present %v) in the registry", name, n, got, ok)
		}
	}
	fmt.Printf("%-18s %d rows, %d compared\n", "bounds.json", len(v.Bounds), len(ours))
}
