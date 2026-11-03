// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

// The ZX Spectrum Next's logo: the light clipboard (apps/design/icon/light.png)
// on the ULA screen, which .cbb install shows while it works, drawn as
// Spectrum artists draw: on black, each 8 by 8 cell in two of the eight
// colours, all of them bright or none (the attribute clash), and the
// shades between the two in an ordered 4 by 4 dither, so that the board's
// gold comes out as yellow over red. Each cell takes the pair, the
// brightness and the dither that look nearest the drawing from a little
// way off: the error is taken in CIELAB on the 2 by 2 averages, with a
// little of each pixel's own. It is written as a C header: the bitmap a
// pixel row at a time, the leftmost pixel in a byte's top bit, then an
// attribute byte for each cell, packed as PackBits does (zxPack), since
// .cbb has little memory to spare.

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
	zxCols, zxRows = 14, 18
)

var (
	// The colours the logo may use: black, blue, red, cyan, yellow and
	// white (magenta and green only add noise to this drawing).
	zxAllowed = []int{0, 1, 2, 5, 6, 7}
	// Bayer's 4 by 4 ordered dither, thresholds in sixteenths.
	zxBayer = [4][4]float64{{0, 8, 2, 10}, {12, 4, 14, 6}, {3, 11, 1, 9}, {15, 7, 13, 5}}
)

// zxRGB is a ULA colour, normal (0xD7) or bright (0xFF).
func zxRGB(c int, bright bool) [3]float64 {
	v := 215.0
	if bright {
		v = 255
	}
	return [3]float64{float64(c>>1&1) * v, float64(c>>2&1) * v, float64(c&1) * v}
}

// zxPixels is the drawing scaled into the logo's cells on black, each
// pixel the average of 4 by 4 samples, then livened as an artist would:
// more saturated, more contrast, a little brighter.
func zxPixels(img image.Image) [][3]float64 {
	src := opaqueBounds(img)
	w, h := zxCols*8, zxRows*8
	scale := math.Max(float64(src.Dx())/float64(w), float64(src.Dy())/float64(h))
	offX := (float64(w) - float64(src.Dx())/scale) / 2
	offY := (float64(h) - float64(src.Dy())/scale) / 2
	out := make([][3]float64, w*h)
	var mean float64
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var sum [4]float64
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					fx := (float64(x)-offX+(float64(sx)+0.5)/4)*scale + float64(src.Min.X)
					fy := (float64(y)-offY+(float64(sy)+0.5)/4)*scale + float64(src.Min.Y)
					s := sample(img, src, fx, fy)
					for i := range sum {
						sum[i] += s[i]
					}
				}
			}
			p := &out[y*w+x]
			for i := range 3 {
				// Premultiplied on black: the colour as it is.
				p[i] = sum[i] / 16 / 0xFFFF * 0xFF
			}
			mean += zxLuma(*p)
		}
	}
	mean /= float64(w * h)
	for i, p := range out {
		l := zxLuma(p)
		for k := range 3 {
			c := l + (p[k]-l)*1.4    // saturation
			c = mean + (c-mean)*1.15 // contrast
			c *= 1.15                // brightness
			out[i][k] = math.Max(0, math.Min(255, c))
		}
	}
	return out
}

func zxLuma(p [3]float64) float64 { return 0.299*p[0] + 0.587*p[1] + 0.114*p[2] }

// zxLab is the colour in CIELAB (D65).
func zxLab(p [3]float64) [3]float64 {
	var lin [3]float64
	for i, c := range p {
		c /= 255
		if c > 0.04045 {
			c = math.Pow((c+0.055)/1.055, 2.4)
		} else {
			c /= 12.92
		}
		lin[i] = c
	}
	xyz := [3]float64{
		(0.4124*lin[0] + 0.3576*lin[1] + 0.1805*lin[2]) / 0.9505,
		0.2126*lin[0] + 0.7152*lin[1] + 0.0722*lin[2],
		(0.0193*lin[0] + 0.1192*lin[1] + 0.9505*lin[2]) / 1.089,
	}
	for i, v := range xyz {
		if v > 0.008856 {
			xyz[i] = math.Cbrt(v)
		} else {
			xyz[i] = 7.787*v + 16.0/116
		}
	}
	return [3]float64{116*xyz[1] - 16, 500 * (xyz[0] - xyz[1]), 200 * (xyz[1] - xyz[2])}
}

func zxLabDist(a, b [3]float64) float64 {
	la, lb := zxLab(a), zxLab(b)
	d0, d1, d2 := la[0]-lb[0], la[1]-lb[1], la[2]-lb[2]
	return d0*d0 + d1*d1 + d2*d2
}

// zxCell draws one cell: the ink's pixels set in bits, and its attribute.
func zxCell(cell *[8][8][3]float64) (bits [8]byte, attr byte) {
	best := math.Inf(1)
	for _, bright := range []bool{false, true} {
		for ai, a := range zxAllowed {
			for _, b := range zxAllowed[ai+1:] {
				pa, pb := zxRGB(a, bright), zxRGB(b, bright)
				var res [8][8][3]float64
				var set [8]byte
				d := [3]float64{pb[0] - pa[0], pb[1] - pa[1], pb[2] - pa[2]}
				dd := d[0]*d[0] + d[1]*d[1] + d[2]*d[2]
				for y := range 8 {
					for x := range 8 {
						p := cell[y][x]
						t := ((p[0]-pa[0])*d[0] + (p[1]-pa[1])*d[1] + (p[2]-pa[2])*d[2]) / dd
						res[y][x] = pa
						if t > (zxBayer[y&3][x&3]+0.5)/16 {
							res[y][x] = pb
							set[y] |= 0x80 >> x
						}
					}
				}
				e := 0.0
				for y := 0; y < 7; y++ {
					for x := 0; x < 7; x++ {
						e += zxLabDist(zxAverage(&res, x, y), zxAverage(cell, x, y))
					}
				}
				for y := range 8 {
					for x := range 8 {
						e += 0.1 * zxLabDist(res[y][x], cell[y][x])
					}
				}
				if !bright {
					e *= 1.05
				}
				// The page: black lines on white are always bright.
				if a == 0 && b == 7 && !bright {
					continue
				}
				if e < best {
					best, bits = e, set
					// b, the ink, is where the bits are set.
					attr = byte(a)<<3 | byte(b)
					if bright {
						attr |= 0x40
					}
				}
			}
		}
	}
	return bits, attr
}

func zxAverage(c *[8][8][3]float64, x, y int) [3]float64 {
	var s [3]float64
	for _, p := range [][3]float64{c[y][x], c[y][x+1], c[y+1][x], c[y+1][x+1]} {
		for i := range 3 {
			s[i] += p[i] / 4
		}
	}
	return s
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
	for cy := range zxRows {
		for cx := range zxCols {
			var cell [8][8][3]float64
			for y := range 8 {
				for x := range 8 {
					cell[y][x] = px[(cy*8+y)*w+cx*8+x]
				}
			}
			bits, attr := zxCell(&cell)
			attrs[cy*zxCols+cx] = attr
			for y := range 8 {
				bitmap[(cy*8+y)*zxCols+cx] = bits[y]
			}
		}
	}
	var b strings.Builder
	b.WriteString("// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (C) 2026 HunterEwok\n\n")
	b.WriteString("// Made by tools/icon (zx.go) from apps/design/icon/light.png; do not edit.\n\n")
	fmt.Fprintf(&b, "#define LOGO_COLS %d\n#define LOGO_ROWS %d\n", zxCols, zxRows)
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
