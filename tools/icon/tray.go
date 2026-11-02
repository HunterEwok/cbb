// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

// The single-colour glyph of the Mac's menu bar and of the tray on Windows
// and Linux, drawn in apps/design/icon/tray: the clipboard with its key on an
// 18 by 18 point canvas, black with alpha, one path of straight segments
// filled even-odd. It comes in three states: tray (no group, or a problem),
// tray-group (in a group, no other device online) and tray-online (another
// device online).
//
// For the Mac it copies each drawing into the app's asset catalog, where the
// image set renders it as a template that the system tints for light and
// dark menu bars. For Linux it writes a symbolic icon, which the panel
// recolours. For Windows, which takes neither, it writes an ICO in white for
// dark taskbars and one in black for light ones, at 16, 20, 24, 32 and 48
// pixels.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	trayDrawings = "apps/design/icon/tray/"
	macTray      = "apps/macos/ClipboardBridgeMac/Resources/Assets.xcassets/"
	desktopTray  = "apps/desktop/trayicon/"
	// The drawings' canvas, in points.
	trayCanvas = 18
)

var (
	trayStates = []struct{ drawing, mac string }{
		{"tray", "Tray"},
		{"tray-group", "TrayGroup"},
		{"tray-online", "TrayOnline"},
	}
	traySizes = []int{16, 20, 24, 32, 48}
	trayPath  = regexp.MustCompile(` d="([^"]*)"`)
	// Adwaita's foreground, the colour symbolic icons are drawn in.
	symbolicFill = "#2e3436"
)

// trayOutputs returns every file made from the tray drawings, by path.
func trayOutputs() (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, s := range trayStates {
		name := trayDrawings + s.drawing + ".svg"
		svg, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		shape, err := parsePath(svg)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		if !bytes.Contains(svg, []byte(`fill="#000"`)) {
			return nil, fmt.Errorf("%s: the drawing is not filled black", name)
		}
		out[macTray+s.mac+".imageset/"+s.drawing+".svg"] = svg
		out[macTray+s.mac+".imageset/Contents.json"] = imageSet(s.drawing + ".svg")
		symbolic := strings.Replace(string(svg), `fill="#000"`, `fill="`+symbolicFill+`"`, 1)
		linux := strings.Replace(s.drawing, "tray", "clipboardbridge", 1) + "-symbolic.svg"
		out[desktopTray+linux] = []byte(symbolic)
		for _, c := range []struct {
			name string
			col  color.NRGBA
		}{{"white", color.NRGBA{0xFF, 0xFF, 0xFF, 0}}, {"black", color.NRGBA{0, 0, 0, 0}}} {
			ico, err := makeICO(shape, c.col)
			if err != nil {
				return nil, err
			}
			out[desktopTray+s.drawing+"-"+c.name+".ico"] = ico
		}
	}
	return out, nil
}

// imageSet is the Contents.json of a template image set with one vector
// drawing.
func imageSet(file string) []byte {
	return []byte(`{
  "images" : [
    {
      "filename" : "` + file + `",
      "idiom" : "universal"
    }
  ],
  "info" : {
    "author" : "xcode",
    "version" : 1
  },
  "properties" : {
    "preserves-vector-representation" : true,
    "template-rendering-intent" : "template"
  }
}
`)
}

type point struct{ x, y float64 }

// parsePath reads the polygons of the drawing's one path: M, L and Z with
// absolute coordinates, the only commands the drawings use.
func parsePath(svg []byte) ([][]point, error) {
	m := trayPath.FindSubmatch(svg)
	if m == nil {
		return nil, fmt.Errorf("no path")
	}
	var shape [][]point
	fields := strings.FieldsFunc(string(m[1]), func(r rune) bool { return r == ' ' || r == ',' })
	for i := 0; i < len(fields); {
		f := fields[i]
		switch {
		case f == "Z":
			i++
			continue
		case f[0] == 'M':
			shape = append(shape, nil)
			fields[i] = f[1:]
		case f[0] == 'L':
			fields[i] = f[1:]
		}
		if len(shape) == 0 || i+1 >= len(fields) {
			return nil, fmt.Errorf("bad path near %q", f)
		}
		x, err1 := strconv.ParseFloat(fields[i], 64)
		y, err2 := strconv.ParseFloat(strings.TrimSuffix(fields[i+1], "Z"), 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("bad point %s,%s", fields[i], fields[i+1])
		}
		shape[len(shape)-1] = append(shape[len(shape)-1], point{x, y})
		i += 2
	}
	return shape, nil
}

// rasterize fills shape even-odd on a size by size image of col, each pixel's
// alpha the share of its 16 by 16 samples inside the shape.
func rasterize(shape [][]point, size int, col color.NRGBA) *image.NRGBA {
	const sub = 16
	scale := float64(size) / trayCanvas
	cover := make([]int, size*size)
	var xs []float64
	for sy := 0; sy < size*sub; sy++ {
		y := (float64(sy) + 0.5) / sub / scale
		xs = xs[:0]
		for _, poly := range shape {
			for i := range poly {
				a, b := poly[i], poly[(i+1)%len(poly)]
				if (a.y <= y) != (b.y <= y) {
					xs = append(xs, (a.x+(y-a.y)/(b.y-a.y)*(b.x-a.x))*scale)
				}
			}
		}
		slices.Sort(xs)
		row := sy / sub * size
		for i := 0; i+1 < len(xs); i += 2 {
			// The samples at (n+0.5)/sub between the two crossings.
			from := int(math.Ceil(xs[i]*sub - 0.5))
			to := int(math.Ceil(xs[i+1]*sub - 0.5))
			for sx := max(from, 0); sx < min(to, size*sub); sx++ {
				cover[row+sx/sub]++
			}
		}
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for i, c := range cover {
		col.A = uint8((c*255 + sub*sub/2) / (sub * sub))
		img.SetNRGBA(i%size, i/size, col)
	}
	return img
}

// makeICO writes an ICO with a PNG of the shape at each of traySizes.
func makeICO(shape [][]point, col color.NRGBA) ([]byte, error) {
	var pngs [][]byte
	for _, size := range traySizes {
		var b bytes.Buffer
		if err := png.Encode(&b, rasterize(shape, size, col)); err != nil {
			return nil, err
		}
		pngs = append(pngs, b.Bytes())
	}
	var out bytes.Buffer
	le := binary.LittleEndian
	out.Write(le.AppendUint16(le.AppendUint16(le.AppendUint16(nil, 0), 1), uint16(len(pngs))))
	offset := 6 + 16*len(pngs)
	for i, p := range pngs {
		size := byte(traySizes[i])
		entry := []byte{size, size, 0, 0}
		entry = le.AppendUint16(entry, 1)  // colour planes
		entry = le.AppendUint16(entry, 32) // bits per pixel
		entry = le.AppendUint32(entry, uint32(len(p)))
		entry = le.AppendUint32(entry, uint32(offset))
		out.Write(entry)
		offset += len(p)
	}
	for _, p := range pngs {
		out.Write(p)
	}
	return out.Bytes(), nil
}
