// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
)

// imageBoard is a fake clipboard that takes images.
type imageBoard struct {
	*fakeBoard
	images chan Image
}

func (b *imageBoard) WriteImage(img Image, text string) error {
	b.mu.Lock()
	b.item, b.has, b.ownWrite = Item{Text: text, Image: &img}, true, true
	b.mu.Unlock()
	b.images <- img
	return nil
}

// copyImage copies an image on the service as cbb copy -type does.
func copyImage(t *testing.T, socket string, img Image, text string) {
	t.Helper()
	c, err := control.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Send(&control.Message{Header: control.Header{Op: control.OpCopyMedia}, Payload: []byte(text)})
	c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Part: &control.Part{Type: img.Type, Size: int64(len(img.Data))}}})
	c.Send(&control.Message{Header: control.Header{Op: control.OpData}, Payload: img.Data})
	c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Done: true}})
	if _, err := c.Receive(); err != nil {
		t.Fatal(err)
	}
}

// TestImages: an image copied on the desktop reaches the service, and one
// copied with cbb copy -type reaches the desktop, while a board without
// images gets the text that goes with it.
func TestImages(t *testing.T) {
	socket := startService(t)
	b := &imageBoard{fakeBoard: newBoard(), images: make(chan Image, 4)}
	run(t, socket, b)
	plain := newBoard()
	run(t, socket, plain)
	plain.copyOn(Item{Text: "the plain board watches"})
	waitFor(t, "the plain board", func() bool { return paste(t, socket) == "the plain board watches" })

	png := Image{Type: clip.TypePNG, Data: make([]byte, 3<<20+7)}
	rand.Read(png.Data)
	b.copyOn(Item{Image: &png})
	waitFor(t, "the desktop's image", func() bool {
		got, err := fetchMedia(t.Context(), socket, nil)
		return err == nil && got.image != nil && bytes.Equal(got.image.Data, png.Data)
	})

	jpeg := Image{Type: clip.TypeJPEG, Data: []byte("not really a JPEG")}
	copyImage(t, socket, jpeg, "a photo")
	select {
	case img := <-b.images:
		if img.Type != jpeg.Type || !bytes.Equal(img.Data, jpeg.Data) {
			t.Errorf("wrote %s of %d bytes", img.Type, len(img.Data))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the image did not reach the desktop")
	}
	if it, _, _ := b.Current(); it.Text != "a photo" {
		t.Errorf("the image's text is %q", it.Text)
	}
	expectWrite(t, plain, "a photo", false)

	// A text after the image replaces it.
	do(t, socket, control.Header{Op: control.OpCopy}, "a text again")
	expectWrite(t, b.fakeBoard, "a text again", false)
}
