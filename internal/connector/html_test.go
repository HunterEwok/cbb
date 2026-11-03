// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import (
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
)

// htmlBoard is a fake clipboard that takes formatted text.
type htmlBoard struct {
	*fakeBoard
	html chan [2]string
}

func (b *htmlBoard) WriteHTML(html, text string) error {
	b.mu.Lock()
	b.item, b.has, b.ownWrite = Item{Text: text, HTML: html}, true, true
	b.mu.Unlock()
	b.html <- [2]string{html, text}
	return nil
}

// TestHTML: formatted text copied on the desktop reaches the service with
// its plain text, and one copied with cbb copy reaches the desktop, while
// a board without it gets the plain text; formatted text whose plain text
// is too large for the alternative, or a secret's, goes as that text.
func TestHTML(t *testing.T) {
	socket := startService(t)
	b := &htmlBoard{fakeBoard: newBoard(), html: make(chan [2]string, 4)}
	run(t, socket, b)
	plain := newBoard()
	run(t, socket, plain)
	plain.copyOn(Item{Text: "the plain board watches"})
	waitFor(t, "the plain board", func() bool { return paste(t, socket) == "the plain board watches" })

	html := "<p>Hello, <b>world</b></p>"
	b.copyOn(Item{Text: "Hello, world", HTML: html})
	waitFor(t, "the desktop's formatted text", func() bool {
		got, err := fetchMedia(t.Context(), socket, nil)
		return err == nil && got.html == html && got.text == "Hello, world"
	})
	if got := paste(t, socket); got != "Hello, world" {
		t.Errorf("paste gives %q", got)
	}

	other := "<ul><li>one</li></ul>"
	copyImage(t, socket, Image{Type: clip.TypeHTML, Data: []byte(other)}, "one")
	select {
	case got := <-b.html:
		if got != [2]string{other, "one"} {
			t.Errorf("wrote %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the formatted text did not reach the desktop")
	}
	expectWrite(t, plain, "one", false)

	// A plain text over the alternative's limit goes alone, and so does a
	// secret.
	long := strings.Repeat("x", clip.MaxAltText+1)
	b.copyOn(Item{Text: long, HTML: "<p>" + long + "</p>"})
	waitFor(t, "the long text", func() bool { return paste(t, socket) == long })
	if _, err := fetchMedia(t.Context(), socket, nil); err == nil {
		t.Error("the long text went as formatted text")
	}
	b.copyOn(Item{Text: "a password", HTML: "<b>a password</b>", Secret: true})
	do(t, socket, control.Header{Op: control.OpCopy}, "after the secret")
	expectWrite(t, b.fakeBoard, "after the secret", false)
}
