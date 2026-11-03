// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

// The ZX Spectrum Next's logo: the tray glyph (apps/design/icon/tray/tray.svg)
// in one bit a pixel, which .cbb install draws on the ULA screen. It is
// written as a C header of zxLogoSize rows of zxLogoSize/8 bytes, the
// leftmost pixel in a byte's top bit, as the screen holds them.

import (
	"fmt"
	"os"
	"strings"
)

const (
	zxLogo     = "apps/zxnext/src/logo.h"
	zxLogoSize = 48
)

func zxLogoOutput() (map[string][]byte, error) {
	name := trayDrawings + "tray.svg"
	svg, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	shape, err := parsePath(svg)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	img := rasterize(shape, zxLogoSize, zxBlack)
	var b strings.Builder
	b.WriteString("// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (C) 2026 HunterEwok\n\n")
	b.WriteString("// Made by tools/icon from apps/design/icon/tray/tray.svg; do not edit.\n\n")
	fmt.Fprintf(&b, "#define LOGO_SIZE %d\n\nstatic const unsigned char logo[] = {\n", zxLogoSize)
	for y := 0; y < zxLogoSize; y++ {
		b.WriteString("   ")
		for x := 0; x < zxLogoSize; x += 8 {
			var v byte
			for i := 0; i < 8; i++ {
				// Half covered or more: the pixel is set.
				if img.NRGBAAt(x+i, y).A >= 128 {
					v |= 0x80 >> i
				}
			}
			fmt.Fprintf(&b, " 0x%02X,", v)
		}
		b.WriteString("\n")
	}
	b.WriteString("};\n")
	return map[string][]byte{zxLogo: []byte(b.String())}, nil
}
