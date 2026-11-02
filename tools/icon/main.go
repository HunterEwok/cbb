// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command icon makes the apps' icons from the drawings in apps/design/icon:
// each clipboard, light and dark, cut out of its transparent margin and set
// on a fill of its own colour, so that the system's mask rounds the fill and
// not the drawing. The clipboard's board sits in the middle, as far from the
// top edge as from the bottom one; the clip above it reaches into the top
// margin. For the iPhone it writes opaque 1024 by 1024 PNGs, the
// light one for the system's light mode and the dark one for dark mode; for
// the watch an opaque one with a smaller board, which the watch's round mask
// leaves whole. For the Mac, whose system draws no mask, it writes the
// rounded square of macOS's icon grid (824 of 1024 pixels, a corner of 185)
// on a transparent canvas, at every size the Mac's icon set takes. For
// Android it writes the foreground of the adaptive icon, the light clipboard
// on a transparent 432 by 432 canvas inside the launcher's safe zone; the
// fill is the icon's background colour in res/values/ic_launcher.xml.
// The single-colour glyph of the menu bar and the tray is in tray.go.
//
//	go run ./tools/icon          rewrite the icons
//	go run ./tools/icon -check   fail if they are out of date
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

const (
	appIcon     = "apps/ios/ClipboardBridge/Resources/Assets.xcassets/AppIcon.appiconset/"
	watchIcon   = "apps/ios/Watch/Assets.xcassets/AppIcon.appiconset/"
	macIcon     = "apps/macos/ClipboardBridgeMac/Resources/Assets.xcassets/AppIcon.appiconset/"
	androidIcon = "apps/android/shared/src/main/res/mipmap-xxxhdpi/ic_launcher_foreground.png"
)

// The light theme's background, the icon's fill.
var paper = color.RGBA{0xF5, 0xF0, 0xE4, 0xFF}

type iconSpec struct {
	drawing, out string
	fill         color.RGBA
	// size is the image's width and height in pixels; height the
	// board's height, of the image, without the clip.
	size   int
	height float64
	// mac sets the drawing in macOS's rounded square and writes it at
	// each of the Mac's sizes, out naming the 1024 pixel one.
	mac bool
}

var icons = []iconSpec{
	{"apps/design/icon/light.png", appIcon + "AppIcon.png", paper, 1024, 0.78, false},
	// The terminal theme's background (apps/design/tokens.json).
	{"apps/design/icon/dark.png", appIcon + "AppIcon-Dark.png", color.RGBA{0x0A, 0x0F, 0x0C, 0xFF}, 1024, 0.78, false},
	// The watch's circle cuts the corners: a board of 0.6 keeps its own.
	{"apps/design/icon/light.png", watchIcon + "AppIcon.png", paper, 1024, 0.6, false},
	{"apps/design/icon/light.png", macIcon + "AppIcon-512@2x.png", paper, 1024, 0.78, true},
	// 108 dp with the inner 66 dp always shown, at 4 pixels a dp: a
	// transparent fill, as the launcher draws the background below.
	{"apps/design/icon/light.png", androidIcon, color.RGBA{}, 432, 0.5, false},
}

// opaqueBounds is the smallest rectangle holding every pixel of img that is
// not fully transparent.
func opaqueBounds(img image.Image) image.Rectangle {
	b := img.Bounds()
	r := image.Rectangle{Min: b.Max, Max: b.Min}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0 {
				r = r.Union(image.Rect(x, y, x+1, y+1))
			}
		}
	}
	return r
}

// board is the rows of src that hold the board: those at least half as wide
// as the widest, which leaves out the narrower clip above it.
func board(img image.Image, src image.Rectangle) (top, bottom int) {
	widths := make([]int, src.Dy())
	widest := 0
	for y := src.Min.Y; y < src.Max.Y; y++ {
		left, right := src.Max.X, src.Min.X
		for x := src.Min.X; x < src.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0 {
				left, right = min(left, x), max(right, x+1)
			}
		}
		widths[y-src.Min.Y] = max(right-left, 0)
		widest = max(widest, right-left)
	}
	top, bottom = src.Max.Y, src.Min.Y
	for i, w := range widths {
		if 2*w >= widest {
			top, bottom = min(top, src.Min.Y+i), max(bottom, src.Min.Y+i+1)
		}
	}
	return top, bottom
}

// sample is img's premultiplied colour at (x, y), interpolated between the
// four nearest pixels; outside src it is transparent.
func sample(img image.Image, src image.Rectangle, x, y float64) [4]float64 {
	x0, y0 := math.Floor(x-0.5), math.Floor(y-0.5)
	fx, fy := x-0.5-x0, y-0.5-y0
	var out [4]float64
	for _, p := range [4]struct{ dx, dy int }{{0, 0}, {1, 0}, {0, 1}, {1, 1}} {
		px, py := int(x0)+p.dx, int(y0)+p.dy
		if !image.Pt(px, py).In(src) {
			continue
		}
		wx, wy := 1-fx, 1-fy
		if p.dx == 1 {
			wx = fx
		}
		if p.dy == 1 {
			wy = fy
		}
		w := wx * wy
		r, g, b, a := img.At(px, py).RGBA()
		out[0] += w * float64(r)
		out[1] += w * float64(g)
		out[2] += w * float64(b)
		out[3] += w * float64(a)
	}
	return out
}

// compose draws the clipboard on fill, premultiplied; a transparent fill
// keeps the drawing's own transparency.
func compose(drawing image.Image, fill color.RGBA, size int, height float64) *image.RGBA {
	src := opaqueBounds(drawing)
	boardTop, boardBottom := board(drawing, src)
	n := float64(size)
	scale := n * height / float64(boardBottom-boardTop)
	w := float64(src.Dx()) * scale
	// top is where src's top row lands: the clip's top, above the board's.
	left := (n - w) / 2
	top := (n-n*height)/2 - float64(boardTop-src.Min.Y)*scale
	if top < 0 {
		panic(fmt.Sprintf("icon: the clip does not fit above a board of height %v", height))
	}
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			x := float64(src.Min.X) + (float64(px)+0.5-left)/scale
			y := float64(src.Min.Y) + (float64(py)+0.5-top)/scale
			c := sample(drawing, src, x, y)
			a := c[3] / 0xffff
			mix := func(v float64, f uint8) uint8 {
				return uint8(math.Round(v/0xffff*0xff + (1-a)*float64(f)))
			}
			alpha := uint8(math.Round(a*0xff + (1-a)*float64(fill.A)))
			img.SetRGBA(px, py, color.RGBA{mix(c[0], fill.R), mix(c[1], fill.G), mix(c[2], fill.B), alpha})
		}
	}
	return img
}

func encode(img image.Image) []byte {
	var buf bytes.Buffer
	// An opaque image is written without an alpha channel, as the App
	// Store requires.
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// macSquare is macOS's icon: img, opaque and 824 pixels square, cut to a
// rounded square with corners of 185 pixels, in the middle of a transparent
// 1024 pixel canvas.
func macSquare(img *image.RGBA) *image.RGBA {
	const canvas, side, radius = 1024, 824, 185.0
	off := (canvas - side) / 2
	out := image.NewRGBA(image.Rect(0, 0, canvas, canvas))
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			// Coverage of the pixel by the rounded square, from the distance
			// of its centre to the nearest corner's circle.
			cx := math.Max(0, math.Abs(float64(x)+0.5-side/2)-(side/2-radius))
			cy := math.Max(0, math.Abs(float64(y)+0.5-side/2)-(side/2-radius))
			cover := math.Min(1, math.Max(0, radius+0.5-math.Hypot(cx, cy)))
			c := img.RGBAAt(x, y)
			k := func(v uint8) uint8 { return uint8(math.Round(float64(v) * cover)) }
			out.SetRGBA(x+off, y+off, color.RGBA{k(c.R), k(c.G), k(c.B), k(c.A)})
		}
	}
	return out
}

// shrink is img, premultiplied and square, scaled down to size pixels by
// averaging the source pixels under each target pixel.
func shrink(img *image.RGBA, size int) *image.RGBA {
	n := img.Bounds().Dx()
	out := image.NewRGBA(image.Rect(0, 0, size, size))
	f := float64(n) / float64(size)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var sum [4]float64
			var w float64
			for y := int(float64(py) * f); y < int(math.Ceil(float64(py+1)*f)) && y < n; y++ {
				wy := math.Min(float64(y+1), float64(py+1)*f) - math.Max(float64(y), float64(py)*f)
				for x := int(float64(px) * f); x < int(math.Ceil(float64(px+1)*f)) && x < n; x++ {
					wx := math.Min(float64(x+1), float64(px+1)*f) - math.Max(float64(x), float64(px)*f)
					c := img.RGBAAt(x, y)
					sum[0] += wx * wy * float64(c.R)
					sum[1] += wx * wy * float64(c.G)
					sum[2] += wx * wy * float64(c.B)
					sum[3] += wx * wy * float64(c.A)
					w += wx * wy
				}
			}
			v := func(i int) uint8 { return uint8(math.Round(sum[i] / w)) }
			out.SetRGBA(px, py, color.RGBA{v(0), v(1), v(2), v(3)})
		}
	}
	return out
}

// macSizes are the Mac icon set's images: points and scale.
var macSizes = []struct{ points, scale int }{
	{16, 1}, {16, 2}, {32, 1}, {32, 2}, {128, 1}, {128, 2}, {256, 1}, {256, 2}, {512, 1}, {512, 2},
}

func macName(points, scale int) string {
	if scale == 1 {
		return fmt.Sprintf("AppIcon-%d.png", points)
	}
	return fmt.Sprintf("AppIcon-%d@%dx.png", points, scale)
}

// outputs is what icon writes: each file and its bytes.
func outputs(icon iconSpec, drawing image.Image) map[string][]byte {
	if !icon.mac {
		return map[string][]byte{icon.out: encode(compose(drawing, icon.fill, icon.size, icon.height))}
	}
	full := macSquare(compose(drawing, icon.fill, 824, icon.height))
	files := map[string][]byte{}
	for _, s := range macSizes {
		img := full
		if px := s.points * s.scale; px != 1024 {
			img = shrink(full, px)
		}
		files[macIcon+macName(s.points, s.scale)] = encode(img)
	}
	return files
}

func main() {
	check := flag.Bool("check", false, "fail if the icons are out of date")
	flag.Parse()
	for _, icon := range icons {
		f, err := os.Open(icon.drawing)
		if err != nil {
			fmt.Fprintln(os.Stderr, "icon:", err)
			os.Exit(1)
		}
		drawing, err := png.Decode(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "icon: %s: %v\n", icon.drawing, err)
			os.Exit(1)
		}
		write(outputs(icon, drawing), *check)
	}
	tray, err := trayOutputs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "icon:", err)
		os.Exit(1)
	}
	write(tray, *check)
}

// write writes each file, or with check fails if one differs.
func write(files map[string][]byte, check bool) {
	for name, out := range files {
		if check {
			cur, err := os.ReadFile(name)
			if err != nil || !bytes.Equal(cur, out) {
				fmt.Fprintf(os.Stderr, "icon: %s is out of date; run go run ./tools/icon\n", name)
				os.Exit(1)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "icon:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(name, out, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "icon:", err)
			os.Exit(1)
		}
	}
}
