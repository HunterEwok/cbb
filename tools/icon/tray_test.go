// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/binary"
	"image/color"
	"image/png"
	"testing"
)

func TestRasterize(t *testing.T) {
	// A square over the canvas's left half, with a square hole in it.
	shape, err := parsePath([]byte(`<path fill="#000" d="M0,0 L9,0 L9,18 L0,18Z M3,3 L6,3 L6,6 L3,6Z"/>`))
	if err != nil {
		t.Fatal(err)
	}
	img := rasterize(shape, 18, color.NRGBA{0, 0, 0, 0})
	for _, c := range []struct {
		x, y int
		a    uint8
	}{{0, 0, 255}, {8, 17, 255}, {9, 0, 0}, {17, 17, 0}, {4, 4, 0}, {2, 4, 255}} {
		if got := img.NRGBAAt(c.x, c.y).A; got != c.a {
			t.Errorf("alpha at %d,%d = %d, want %d", c.x, c.y, got, c.a)
		}
	}
	// At 12 pixels the edge at 9 points falls between pixels 5 and 6.
	img = rasterize(shape, 12, color.NRGBA{})
	if left, right := img.NRGBAAt(5, 0).A, img.NRGBAAt(6, 0).A; left != 255 || right != 0 {
		t.Errorf("alpha at the edge = %d, %d", left, right)
	}
}

func TestParsePathRejects(t *testing.T) {
	for _, d := range []string{`<path/>`, `<path d="L1,2"/>`, `<path d="M1,x"/>`, `<path d="M1"/>`} {
		if _, err := parsePath([]byte(d)); err == nil {
			t.Errorf("%s: no error", d)
		}
	}
}

func TestTrayOutputs(t *testing.T) {
	t.Chdir("../..")
	out, err := trayOutputs()
	if err != nil {
		t.Fatal(err)
	}
	ico := out[desktopTray+"tray-online-white.ico"]
	le := binary.LittleEndian
	if len(ico) < 6 || le.Uint16(ico[2:]) != 1 || int(le.Uint16(ico[4:])) != len(traySizes) {
		t.Fatalf("bad ICO header")
	}
	for i, size := range traySizes {
		e := ico[6+16*i:]
		n, off := le.Uint32(e[8:]), le.Uint32(e[12:])
		img, err := png.Decode(bytes.NewReader(ico[off : off+n]))
		if err != nil {
			t.Fatal(err)
		}
		if img.Bounds().Dx() != size || int(e[0]) != size {
			t.Errorf("entry %d is %d pixels, want %d", i, img.Bounds().Dx(), size)
		}
	}
	if !bytes.Contains(out[desktopTray+"clipboardbridge-symbolic.svg"], []byte(symbolicFill)) {
		t.Error("the symbolic icon is not in the symbolic colour")
	}
}
