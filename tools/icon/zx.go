// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

// The ZX Spectrum Next's logo: the light clipboard (apps/design/icon/light.png)
// on the ULA screen, which .cbb install shows while it works. The screen
// holds two colours in each 8 by 8 cell, an ink and a paper, from eight;
// each cell takes the pair of zxColours nearest its pixels. The board's
// gold is drawn in brown, which .cbb sets in the Next's ULA palette in
// place of yellow while the logo shows (zxBrown, as RRRGGGBBB). It is
// written as a C header: the bitmap a pixel row at a time, the leftmost
// pixel in a byte's top bit, then an attribute byte for each cell, packed
// as PackBits does (zxPack), since .cbb has little memory to spare.

import (
	"fmt"
	"image"
	"image/png"
	"math"
	"os"
	"strings"
)

const (
	zxLogo = "apps/zxnext/src/logo.h"
	// The logo's size in cells of 8 by 8 pixels.
	zxCols, zxRows = 12, 15
	// The Next's 9-bit colour for the ULA's yellow meanwhile.
	zxBrown = 4<<6 | 2<<3 | 1 // #924924
)

// The ULA colours the logo uses, by their number, with the colour of the
// drawing each stands for.
var zxColours = []struct {
	ula     byte
	r, g, b float64
}{
	{0, 0x00, 0x00, 0x00}, // black: the lines
	{6, 0xC8, 0xA0, 0x40}, // yellow, set to brown: the board's gold
	{7, 0xF5, 0xF2, 0xEA}, // white: the page and the screen
}

// zxPixels is the drawing scaled into the logo's cells, each pixel the
// average of the drawing's pixels it covers, on white.
func zxPixels(img image.Image) [][3]float64 {
	src := opaqueBounds(img)
	w, h := zxCols*8, zxRows*8
	scale := math.Max(float64(src.Dx())/float64(w), float64(src.Dy())/float64(h))
	offX := (float64(w) - float64(src.Dx())/scale) / 2
	offY := (float64(h) - float64(src.Dy())/scale) / 2
	white := zxColours[2]
	out := make([][3]float64, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var sum [4]float64
			n := 0
			// 4 by 4 samples in each pixel.
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					fx := (float64(x)-offX+(float64(sx)+0.5)/4)*scale + float64(src.Min.X)
					fy := (float64(y)-offY+(float64(sy)+0.5)/4)*scale + float64(src.Min.Y)
					s := sample(img, src, fx, fy)
					for i := range sum {
						sum[i] += s[i]
					}
					n++
				}
			}
			a := sum[3] / float64(n) / 0xFFFF
			for i, bg := range []float64{white.r, white.g, white.b} {
				out[y*w+x][i] = sum[i]/float64(n)/0xFFFF*0xFF + (1-a)*bg
			}
		}
	}
	return out
}

func zxDistance(p [3]float64, c int) float64 {
	k := zxColours[c]
	dr, dg, db := p[0]-k.r, p[1]-k.g, p[2]-k.b
	return dr*dr + dg*dg + db*db
}

func zxLogoOutput() (map[string][]byte, error) {
	f, err := os.Open("apps/design/icon/light.png")
	if err != nil {
		return nil, err
	}
	img, err := png.Decode(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	px := zxPixels(img)
	w := zxCols * 8
	bitmap := make([]byte, zxRows*8*zxCols)
	attrs := make([]byte, zxRows*zxCols)
	for cy := 0; cy < zxRows; cy++ {
		for cx := 0; cx < zxCols; cx++ {
			// The pair of colours nearest the cell's pixels: ink and paper.
			best, ink, paper := math.Inf(1), 0, 2
			for i := range zxColours {
				for j := range zxColours {
					if i >= j {
						continue
					}
					e := 0.0
					for y := 0; y < 8; y++ {
						for x := 0; x < 8; x++ {
							p := px[(cy*8+y)*w+cx*8+x]
							e += math.Min(zxDistance(p, i), zxDistance(p, j))
						}
					}
					if e < best {
						// The lighter one is the paper.
						best, ink, paper = e, i, j
					}
				}
			}
			attrs[cy*zxCols+cx] = zxColours[paper].ula<<3 | zxColours[ink].ula
			for y := 0; y < 8; y++ {
				var v byte
				for x := 0; x < 8; x++ {
					p := px[(cy*8+y)*w+cx*8+x]
					if zxDistance(p, ink) < zxDistance(p, paper) {
						v |= 0x80 >> x
					}
				}
				bitmap[(cy*8+y)*zxCols+cx] = v
			}
		}
	}
	var b strings.Builder
	b.WriteString("// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (C) 2026 HunterEwok\n\n")
	b.WriteString("// Made by tools/icon (zx.go) from apps/design/icon/light.png; do not edit.\n\n")
	fmt.Fprintf(&b, "#define LOGO_COLS %d\n#define LOGO_ROWS %d\n", zxCols, zxRows)
	fmt.Fprintf(&b, "// The Next's 9-bit colour (RRRGGGBBB) for yellow while it shows.\n")
	fmt.Fprintf(&b, "#define LOGO_BROWN 0x%03X\n\n", zxBrown)
	packed := zxPack(append(bitmap, attrs...))
	fmt.Fprintf(&b, "// The bytes unpacked: the bitmap, then the attributes.\n#define LOGO_BYTES %d\n", len(bitmap)+len(attrs))
	writeBytes(&b, "logo_packed", packed, 16)
	return map[string][]byte{zxLogo: []byte(b.String())}, nil
}

func writeBytes(b *strings.Builder, name string, data []byte, per int) {
	fmt.Fprintf(b, "static const unsigned char %s[] = {\n", name)
	for i := 0; i < len(data); i += per {
		b.WriteString("   ")
		for _, v := range data[i:min(i+per, len(data))] {
			fmt.Fprintf(b, " 0x%02X,", v)
		}
		b.WriteString("\n")
	}
	b.WriteString("};\n")
}

// zxPack packs data as PackBits: a byte n below 128 and n+1 bytes as they
// are, or a byte 257-n (n from 3 to 128) and a byte to repeat n times.
func zxPack(data []byte) []byte {
	var out []byte
	for i := 0; i < len(data); {
		run := 1
		for i+run < len(data) && run < 128 && data[i+run] == data[i] {
			run++
		}
		if run >= 3 {
			out = append(out, byte(257-run), data[i])
			i += run
			continue
		}
		// Bytes as they are, up to the next run of three.
		j := i
		for j < len(data) && j-i < 128 && !(j+2 < len(data) && data[j] == data[j+1] && data[j] == data[j+2]) {
			j++
		}
		out = append(out, byte(j-i-1))
		out = append(out, data[i:j]...)
		i = j
	}
	return out
}
