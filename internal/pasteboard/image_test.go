// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build (darwin && cgo) || windows

package pasteboard

import (
	"bytes"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/HunterEwok/cbb/internal/clip"
)

// TestImage writes images and reads them back: a PNG as it is, a JPEG as
// itself on a Mac and as a PNG on Windows; a text that goes with an image
// is what a read returns.
func TestImage(t *testing.T) {
	b := private(t)
	var p bytes.Buffer
	png.Encode(&p, testImage())
	change, err := b.WriteImage(clip.TypePNG, p.Bytes(), "")
	if err != nil {
		t.Fatal(err)
	}
	it, ok, err := b.Read()
	if err != nil || !ok || it.Change != change || it.ImageType != clip.TypePNG || it.Text != "" {
		t.Fatalf("Read = %+v, %v, %v", it.Change, ok, err)
	}
	img, err := png.Decode(bytes.NewReader(it.Image))
	if err != nil {
		t.Fatal(err)
	}
	samePixels(t, img, testImage())

	var j bytes.Buffer
	jpeg.Encode(&j, testImage(), nil)
	if _, err := b.WriteImage(clip.TypeJPEG, j.Bytes(), ""); err != nil {
		t.Fatal(err)
	}
	if it, ok, err = b.Read(); err != nil || !ok || it.ImageType == "" {
		t.Fatalf("Read after a JPEG = %v, %v, %v", it.ImageType, ok, err)
	}
	if cfg, err := decodeConfig(it.ImageType, it.Image); err != nil || cfg.Width != 3 || cfg.Height != 2 {
		t.Errorf("the JPEG read back as %s: %+v, %v", it.ImageType, cfg, err)
	}

	if _, err := b.WriteImage(clip.TypePNG, p.Bytes(), "a screenshot"); err != nil {
		t.Fatal(err)
	}
	if it, ok, err = b.Read(); err != nil || !ok || it.Text != "a screenshot" || it.ImageType != "" {
		t.Errorf("Read of an image with a text = %q, %q, %v, %v", it.Text, it.ImageType, ok, err)
	}
	if _, err := b.WriteImage(clip.TypePNG, []byte("not an image"), ""); err == nil {
		t.Error("wrote an image that is none")
	}
}
