// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

// The ZX Spectrum Next's logo: the clipboard on the ULA screen, which .cbb
// install shows while it works, drawn as Spectrum artists draw: on black,
// each 8 by 8 cell in two colours (the attribute clash), its shapes on the
// cells' grid so that no cell needs a third. The page's line drawing comes
// from apps/design/icon/light.png as crisp black on bright white. The board
// and the clip are drawn here: a plastic board, a cushion lit from the top
// left with the page's and the clip's shadows to the bottom right, and a
// round clip with its shine a third of the way across, both shaded smoothly
// in an ordered 4 by 4 dither over black. They are in the ULA's red and
// yellow without brightness, which .cbb sets to two browns of the Next's
// palette while the screen shows (cbb.c, palette). It is written as a C
// header: the bitmap a pixel row at a time, the leftmost pixel in a byte's
// top bit, then an attribute byte for each cell, packed as PackBits does
// (zxPack), since .cbb has little memory to spare.

import (
	"fmt"
	"image"
	"image/png"
	"math"
	"os"
	"slices"
	"strings"
)

const (
	zxLogo = "apps/zxnext/src/logo.h"
	// The logo's size in cells of 8 by 8 pixels.
	zxCols, zxRows = 14, 18
	zxW, zxH       = zxCols * 8, zxRows * 8
	// The cells' attributes: the page bright white with black ink, the
	// board's and the clip's ink red and yellow (the browns) on black.
	zxPage, zxBoard, zxClip = 0x40 | 7<<3, 2, 6
)

// Bayer's 4 by 4 ordered dither, thresholds in sixteenths.
var zxBayer = [4][4]float64{{0, 8, 2, 10}, {12, 4, 14, 6}, {3, 11, 1, 9}, {15, 7, 13, 5}}

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
	return out
}

func zxLuma(p [3]float64) float64 { return 0.299*p[0] + 0.587*p[1] + 0.114*p[2] }

// zxField is a value for each pixel of the logo.
type zxField []float64

func (f zxField) at(x, y int) float64 {
	return f[((y%zxH+zxH)%zxH)*zxW+(x%zxW+zxW)%zxW]
}

// zxRoundRect is the signed distance to a rounded rectangle, below 0 inside.
func zxRoundRect(x, y, x0, y0, x1, y1, r float64) float64 {
	cx := math.Max(x0+r, math.Min(x, x1-r))
	cy := math.Max(y0+r, math.Min(y, y1-r))
	return math.Hypot(x-cx, y-cy) - r
}

// zxShapes are the board, the page and the clip, pixel by pixel.
type zxShapes struct {
	board, page, bar, tab, clip, clipEdge []bool
	boardDist                             zxField
}

func zxDraw() zxShapes {
	n := zxW * zxH
	s := zxShapes{make([]bool, n), make([]bool, n), make([]bool, n), make([]bool, n), make([]bool, n), make([]bool, n), make(zxField, n)}
	for y := range zxH {
		for x := range zxW {
			i := y*zxW + x
			fx, fy := float64(x)+0.5, float64(y)+0.5
			s.boardDist[i] = zxRoundRect(fx, fy, 1, 17, 111, 142, 8)
			s.board[i] = s.boardDist[i] < 0
			// The page on the cells' grid, the clip's cells cut out of it.
			s.page[i] = x >= 16 && x < 96 && y >= 32 && y < 128 && !(x >= 24 && x < 88 && y < 40)
			s.bar[i] = fy >= 15 && fy < 39.5 && math.Abs(fx-56.5) < zxClipWidth(fy)
			s.tab[i] = fy < 17 && (math.Hypot(fx-56.5, fy-10.5) < 9 ||
				fy >= 10.5 && math.Abs(fx-56.5) < 9+(fy-10.5)*0.5)
			hole := math.Hypot(fx-56.5, fy-10.5) < 3.8
			s.clip[i] = (s.bar[i] || s.tab[i]) && !hole
		}
	}
	// The clip's outline, and the fold above its lip.
	in := func(m []bool, x, y int) bool { return m[((y+zxH)%zxH)*zxW+(x+zxW)%zxW] }
	for y := range zxH {
		for x := range zxW {
			i := y*zxW + x
			if !s.clip[i] {
				continue
			}
			s.clipEdge[i] = !in(s.clip, x-1, y) || !in(s.clip, x+1, y) || !in(s.clip, x, y-1) || !in(s.clip, x, y+1) ||
				(s.bar[i] && y == 35)
		}
	}
	return s
}

// zxBoardLight is the board's light, 0 dark to 1 light: a cushion with a
// rounded rim lit from the top left, falling a little across the board,
// with the shadows that the page and the clip cast to the bottom right.
func zxBoardLight(s zxShapes) zxField {
	height := make(zxField, zxW*zxH)
	for i, d := range s.boardDist {
		h := math.Max(0, math.Min(1, -d/6))
		height[i] = h * h * (3 - 2*h) * 3
	}
	blur := make(zxField, len(height))
	for y := range zxH {
		for x := range zxW {
			blur[y*zxW+x] = (height.at(x, y) + height.at(x, y-1) + height.at(x, y+1) + height.at(x-1, y) + height.at(x+1, y)) / 5
		}
	}
	// The slope as numpy's gradient takes it: central, one-sided at the edges.
	slope := func(x, y, dx, dy int) float64 {
		x0, y0, x1, y1 := x-dx, y-dy, x+dx, y+dy
		div := 2.0
		if x0 < 0 || y0 < 0 {
			x0, y0, div = x, y, 1
		}
		if x1 >= zxW || y1 >= zxH {
			x1, y1, div = x, y, 1
		}
		return (blur[y1*zxW+x1] - blur[y0*zxW+x0]) / div
	}
	l := [3]float64{-0.55, -0.65, 0.55}
	norm := math.Sqrt(l[0]*l[0] + l[1]*l[1] + l[2]*l[2])
	for i := range l {
		l[i] /= norm
	}
	shades := make([]bool, zxW*zxH)
	for i := range shades {
		shades[i] = s.page[i] || s.clip[i]
	}
	light := make(zxField, zxW*zxH)
	var face []float64
	for y := range zxH {
		for x := range zxW {
			i := y*zxW + x
			gx, gy := slope(x, y, 1, 0), slope(x, y, 0, 1)
			diffuse := (-gx*l[0] - gy*l[1] + l[2]) / math.Sqrt(gx*gx+gy*gy+1)
			fall := 1 - 0.35*((float64(x)+0.5-8)/zxW*0.4+(float64(y)+0.5-17)/zxH*0.6)
			cast := 0.0
			for k := 1; k <= 5; k++ {
				if shades[((y-k+zxH)%zxH)*zxW+(x-k+zxW)%zxW] {
					cast = math.Max(cast, 1-float64(k)/7)
				}
			}
			light[i] = diffuse * fall * (1 - 0.7*cast)
			if s.board[i] && !shades[i] {
				face = append(face, light[i])
			}
		}
	}
	// Spread by rank: the darkest 3 percent black, the lightest 3 full.
	slices.Sort(face)
	q := [3]float64{zxPercentile(face, 3), zxPercentile(face, 50), zxPercentile(face, 97)}
	for i, v := range light {
		switch {
		case v <= q[0]:
			light[i] = 0
		case v < q[1]:
			light[i] = 0.5 * (v - q[0]) / (q[1] - q[0])
		case v < q[2]:
			light[i] = 0.5 + 0.5*(v-q[1])/(q[2]-q[1])
		default:
			light[i] = 1
		}
	}
	return light
}

// zxNextTo tells a pixel beside m, which keeps a black line between the
// clip and the board around it.
func zxNextTo(m []bool, x, y int) bool {
	for _, d := range [4][2]int{{1, 0}, {-1, 0}, {0, 1}, {0, -1}} {
		px, py := x+d[0], y+d[1]
		if px >= 0 && px < zxW && py >= 0 && py < zxH && m[py*zxW+px] {
			return true
		}
	}
	return false
}

// zxPercentile is numpy's percentile of sorted values, linear between them.
func zxPercentile(sorted []float64, p float64) float64 {
	at := p / 100 * float64(len(sorted)-1)
	i := int(at)
	if i+1 >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	return sorted[i] + (at-float64(i))*(sorted[i+1]-sorted[i])
}

// zxClipWidth is half the clip's width at fy: narrow at its top, widening
// in a curve to its lip, the corners rounded.
func zxClipWidth(fy float64) float64 {
	t := (fy - 15) / 24.5
	w := 21 + 11*math.Pow(math.Max(0, t), 1.6)
	w -= math.Max(0, 17-fy)*1.2 + math.Max(0, fy-37)*1.5
	return w
}

// zxClipLight is the clip's light, as on the icon: a polished bar, round
// across with its shine a third of the way in, a light edge along its top,
// its lip folded under in shade; the hump with the hole lit at its top left.
func zxClipLight(s zxShapes, x, y int) float64 {
	fx, fy := float64(x)+0.5, float64(y)+0.5
	i := y*zxW + x
	if s.tab[i] && !s.bar[i] {
		u := (fx - 47) / 19
		return 0.2 + 0.75*math.Max(0, math.Min(1, math.Cos((u-0.35)*2.6)))*(1-(fy-2)/28)
	}
	w := zxClipWidth(fy)
	u := (fx - (56.5 - w)) / (2 * w)
	prof := math.Max(0, math.Min(1, math.Cos((u-0.33)*2.9)))
	v := math.Max(0, math.Min(1, (fy-16)/20))
	f := 0.12 + 0.88*math.Pow(prof, 1.3)*(1-0.35*v)
	if fy < 19 {
		f += 0.2
	}
	if fy >= 36 {
		f = 0.15 + 0.4*prof
	}
	return math.Min(1, f)
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
	s := zxDraw()
	light := zxBoardLight(s)
	// The board's tones run from this much ink to this much.
	const lo, hi = 0.15, 0.95
	bitmap := make([]byte, zxH*zxCols)
	attrs := make([]byte, zxRows*zxCols)
	for cy := range zxRows {
		for cx := range zxCols {
			var page, clip, board bool
			for y := cy * 8; y < cy*8+8; y++ {
				for x := cx * 8; x < cx*8+8; x++ {
					i := y*zxW + x
					page = page || s.page[i]
					clip = clip || s.clip[i]
					board = board || s.board[i]
				}
			}
			var attr byte
			switch {
			case page:
				attr = zxPage
			case clip:
				attr = zxClip
			case board:
				attr = zxBoard
			}
			attrs[cy*zxCols+cx] = attr
			for y := cy * 8; y < cy*8+8; y++ {
				var bits byte
				for x := cx * 8; x < cx*8+8; x++ {
					i := y*zxW + x
					th := (zxBayer[y%4][x%4] + 0.5) / 16
					var on bool
					switch attr {
					case zxPage:
						// The page's lines, as they are.
						on = s.page[i] && px[i].ink > 0.45
					case zxClip:
						on = s.clip[i] && !s.clipEdge[i] && zxClipLight(s, x, y) > th
						// The board in the clip's cells, in the clip's colour: the clash.
						if !s.clip[i] && s.board[i] && !s.page[i] && !s.clipEdge[i] {
							on = lo+(hi-lo)*light[i] > th && !zxNextTo(s.clip, x, y)
						}
					case zxBoard:
						on = s.board[i] && !s.page[i] && !s.clip[i] && lo+(hi-lo)*light[i] > th
					}
					if on {
						bits |= 0x80 >> (x % 8)
					}
				}
				bitmap[y*zxCols+cx] = bits
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
