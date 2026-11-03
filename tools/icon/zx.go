// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

// The ZX Spectrum Next's logo: the light clipboard (apps/design/icon/light.png)
// on the ULA screen, which .cbb install shows while it works, drawn as
// Spectrum artists draw: on black, each 8 by 8 cell in two of the eight
// colours, all of them bright or none (the attribute clash). The page's
// line drawing is kept as crisp black lines on bright white. The board's
// light and shade go onto a ramp of mixes, from red over black to yellow
// over white, so that it keeps its volume; each of its cells then takes
// the pair, the brightness and the ordered 4 by 4 dither that look nearest
// from a little way off: the error is taken in CIELAB on the 2 by 2
// averages, with a little of each pixel's own. It is written as a C
// header: the bitmap a pixel row at a time, the leftmost pixel in a byte's
// top bit, then an attribute byte for each cell, packed as PackBits does
// (zxPack), since .cbb has little memory to spare.

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

// zxPixel is a pixel of the logo: its colour on black, and how much of it
// is the drawing's ink and the page's paper.
type zxPixel struct {
	c          [3]float64
	ink, paper float64
}

// zxPixels is the drawing scaled into the logo's cells on black, each
// pixel 8 by 8 samples.
func zxPixels(img image.Image) []zxPixel {
	src := opaqueBounds(img)
	w, h := zxCols*8, zxRows*8
	scale := math.Max(float64(src.Dx())/float64(w), float64(src.Dy())/float64(h))
	offX := (float64(w) - float64(src.Dx())/scale) / 2
	offY := (float64(h) - float64(src.Dy())/scale) / 2
	out := make([]zxPixel, w*h)
	const n = 8
	for y := range h {
		for x := range w {
			p := &out[y*w+x]
			for sy := range n {
				for sx := range n {
					fx := (float64(x)-offX+(float64(sx)+0.5)/n)*scale + float64(src.Min.X)
					fy := (float64(y)-offY+(float64(sy)+0.5)/n)*scale + float64(src.Min.Y)
					s := sample(img, src, fx, fy)
					// Premultiplied on black: the colour as it is.
					c := [3]float64{s[0] / 0xFFFF, s[1] / 0xFFFF, s[2] / 0xFFFF}
					lum := zxLuma(c)
					sat := max(c[0], c[1], c[2]) - min(c[0], c[1], c[2])
					if c[2] > c[0]+0.08 && lum < 0.45 && s[3]/0xFFFF > 0.5 {
						p.ink++ // the navy lines
					}
					if lum > 0.75 && sat < 0.12 {
						p.paper++
					}
					for i := range 3 {
						p.c[i] += c[i]
					}
				}
			}
			for i := range 3 {
				p.c[i] /= n * n
			}
			p.ink /= n * n
			p.paper /= n * n
		}
	}
	zxShade(out)
	return out
}

// zxShade puts the board's light and shade onto a ramp of the Spectrum's
// mixes, as an artist would, keeping the board's volume, and makes the
// paper bright white. Colours go from 0-1 to 0-255.
func zxShade(px []zxPixel) {
	ramp := [][3]float64{
		{107, 0, 0}, {215, 0, 0}, {215, 54, 0}, // red over black, red, a little yellow
		{255, 128, 0}, {255, 191, 0}, {255, 255, 0}, {255, 255, 128}, // to yellow over white
	}
	board := func(p *zxPixel) bool {
		return 1-min(p.ink+p.paper, 1) > 0.6 && zxLuma(p.c) > 0.04
	}
	var sum, sq, n float64
	for i := range px {
		if board(&px[i]) {
			l := zxLuma(px[i].c)
			sum, sq, n = sum+l, sq+l*l, n+1
		}
	}
	mean := sum / n
	sd := math.Sqrt(sq/n - mean*mean)
	for i := range px {
		p := &px[i]
		switch {
		case p.paper > 0.5:
			p.c = [3]float64{255, 255, 255}
		case board(p):
			at := math.Max(0, math.Min(6, 3.2+(zxLuma(p.c)-mean)/sd*1.2))
			lo := int(at)
			hi := min(lo+1, 6)
			f := at - float64(lo)
			for k := range 3 {
				p.c[k] = ramp[lo][k]*(1-f) + ramp[hi][k]*f
			}
		default:
			for k := range 3 {
				p.c[k] *= 255
			}
		}
	}
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
			var bits [8]byte
			lines, paper := 0, 0.0
			for y := range 8 {
				for x := range 8 {
					p := px[(cy*8+y)*w+cx*8+x]
					cell[y][x] = p.c
					paper += p.paper / 64
					if p.ink > 0.45 {
						lines++
						bits[y] |= 0x80 >> x
					}
				}
			}
			// The page's lines: black on bright white, as they are.
			attr := byte(0x40 | 7<<3)
			if lines < 2 && paper <= 0.7 {
				bits, attr = zxCell(&cell)
			}
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
