// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/png"
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
	watching(t, socket, plain, "the plain board watches")

	png := Image{Type: clip.TypePNG, Data: make([]byte, 3<<20+7)}
	rand.Read(png.Data)
	b.copyOn(Item{Image: &png})
	waitFor(t, "the desktop's image", func() bool {
		got, err := fetchMedia(t.Context(), socket, nil, "")
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

// mediaTarget is a fake target that pastes images and files.
type mediaTarget struct {
	locked bool
	keys   int
}

func (m *mediaTarget) Target() string { return "desktop" }
func (m *mediaTarget) Inject(context.Context, string, string, bool, bool) error {
	return errors.New("a text")
}

func (m *mediaTarget) InjectMedia(_ context.Context, write func() error, enter bool) error {
	if m.locked {
		return &Refusal{Reason: "the session is locked"}
	}
	if err := write(); err != nil {
		return err
	}
	m.keys++
	return nil
}

// textTarget pastes only text.
type textTarget struct{ mediaTarget }

func (textTarget) InjectMedia() {}

// TestInjectedMedia: a remote paste of images or files reaches only a
// target that takes them, fetches the copy it names, and refuses on a
// locked session before it writes the clipboard.
func TestInjectedMedia(t *testing.T) {
	socket := startService(t)
	b := &imageBoard{fakeBoard: newBoard(), images: make(chan Image, 4)}
	m := &control.Message{Header: control.Header{Op: control.OpInject, Seq: 7, Kind: control.KindMedia, Method: "paste"},
		Payload: []byte("0123456789abcdef0123456789abcdef")}
	nop := func(string, ...any) {}
	if ans := injectedMedia(t.Context(), socket, b, &textTarget{}, nil, m, nop); !ans.Refused || ans.Seq != 7 {
		t.Errorf("a text target: %+v", ans.Header)
	}
	if ans := injectedMedia(t.Context(), socket, b, &mediaTarget{locked: true}, nil, m, nop); !ans.Refused || ans.Error != "the session is locked" {
		t.Errorf("a locked session: %+v", ans.Header)
	}
	tgt := &mediaTarget{}
	if ans := injectedMedia(t.Context(), socket, b, tgt, nil, m, nop); ans.Error == "" || ans.Refused || tgt.keys != 0 {
		t.Errorf("a copy that is not the group's: %+v, %d presses", ans.Header, tgt.keys)
	}
}

// A GIF goes on the clipboard as itself and as a PNG of its first frame.
func TestImageForms(t *testing.T) {
	frame := image.NewPaletted(image.Rect(0, 0, 3, 2), color.Palette{color.Black, color.White})
	frame.SetColorIndex(1, 1, 1)
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, &gif.GIF{Image: []*image.Paletted{frame, frame}, Delay: []int{10, 10}}); err != nil {
		t.Fatal(err)
	}
	forms, order := ImageForms(Image{Type: clip.TypeGIF, Data: b.Bytes()})
	if len(order) != 2 || order[0] != clip.TypeGIF || order[1] != clip.TypePNG || !bytes.Equal(forms[clip.TypeGIF], b.Bytes()) {
		t.Fatalf("the forms of a GIF are %v", order)
	}
	img, err := png.Decode(bytes.NewReader(forms[clip.TypePNG]))
	if err != nil {
		t.Fatal(err)
	}
	if r, _, _, _ := img.At(1, 1).RGBA(); img.Bounds() != frame.Bounds() || r != 0xffff {
		t.Errorf("the PNG is %v, with %v at 1,1", img.Bounds(), img.At(1, 1))
	}
	if _, order := ImageForms(Image{Type: clip.TypePNG, Data: []byte("png")}); len(order) != 1 {
		t.Errorf("the forms of a PNG are %v", order)
	}
	if _, order := ImageForms(Image{Type: clip.TypeGIF, Data: []byte("GIF89a")}); len(order) != 1 {
		t.Errorf("the forms of a broken GIF are %v", order)
	}
}
