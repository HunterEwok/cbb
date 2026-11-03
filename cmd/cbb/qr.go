// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"io"
	"strings"

	"rsc.io/qr"
)

// writeQR draws text as a QR code with half blocks, two modules per
// character cell, in black on white whatever the terminal's colors, so a
// phone camera reads it.
func writeQR(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	enableVT(w)
	const quiet = 2
	n := code.Size + 2*quiet
	black := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
	}
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		b.WriteString("  ")
		for x := 0; x < n; x++ {
			// The upper module is the foreground of ▀, the lower one the
			// background.
			fg, bg := "97", "107"
			if black(x, y) {
				fg = "30"
			}
			if black(x, y+1) {
				bg = "40"
			}
			b.WriteString("\x1b[" + fg + ";" + bg + "m▀")
		}
		b.WriteString("\x1b[0m\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
