// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/connector"
)

// imageBoard is a board under test, with the tools that copy and paste
// an image of a type, and list the clipboard's types.
type imageBoard interface {
	connector.Board
	connector.ImageBoard
}

// testImages copies a large image with a tool and reads it, writes one
// and pastes it with the tool, also with a text, and checks that a text
// wins over an image.
func testImages(t *testing.T, b imageBoard, copyAs func(typ string, data []byte), paste func(typ string) []byte, types func() string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Larger than one piece of X11's INCR, which runs in 64 KiB pieces.
	data := make([]byte, 5<<20+3)
	rand.Read(data)

	copyAs(clip.TypePNG, data)
	it, ok, err := b.Next(ctx)
	if err != nil || !ok || it.Image == nil || it.Image.Type != clip.TypePNG || !bytes.Equal(it.Image.Data, data) || it.Text != "" {
		t.Fatalf("Next after an image copy = %v, %v, text %q, image %v", ok, err, it.Text, it.Image != nil)
	}

	jpeg := data[:300<<10]
	if err := b.WriteImage(connector.Image{Type: clip.TypeJPEG, Data: jpeg}, ""); err != nil {
		t.Fatal(err)
	}
	if got := paste(clip.TypeJPEG); !bytes.Equal(got, jpeg) {
		t.Errorf("pasted %d bytes of the JPEG, want %d", len(got), len(jpeg))
	}
	if ts := types(); !strings.Contains(ts, clip.TypeJPEG) || strings.Contains(ts, "text/plain") {
		t.Errorf("the image's types are %q", ts)
	}

	if err := b.WriteImage(connector.Image{Type: clip.TypePNG, Data: data}, "a screenshot"); err != nil {
		t.Fatal(err)
	}
	if got := paste(clip.TypePNG); !bytes.Equal(got, data) {
		t.Errorf("pasted %d bytes of the PNG, want %d", len(got), len(data))
	}
	if got := string(paste("text/plain")); got != "a screenshot" {
		t.Errorf("pasted the text %q", got)
	}
	// Our own writes are no copies.
	ctx2, cancel2 := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel2()
	if it, ok, err := b.Next(ctx2); err == nil {
		t.Errorf("our image write came back: %+v, %v", it.Text, ok)
	}
	if err := b.Write("text again", false); err != nil {
		t.Fatal(err)
	}
	if got := string(paste("text/plain")); got != "text again" {
		t.Errorf("after a text, pasted %q", got)
	}
}

func TestX11Images(t *testing.T) {
	if os.Getenv("CBB_TEST_X11") == "" {
		t.Skip("set CBB_TEST_X11 with an X server in DISPLAY and xclip installed")
	}
	b, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	testImages(t, b, func(typ string, data []byte) {
		cmd := exec.Command("xclip", "-selection", "clipboard", "-t", typ, "-i")
		cmd.Stdin = bytes.NewReader(data)
		if err := cmd.Run(); err != nil {
			t.Fatalf("xclip -i: %v", err)
		}
	}, func(typ string) []byte {
		out, err := exec.Command("xclip", "-selection", "clipboard", "-t", typ, "-o").Output()
		if err != nil {
			t.Errorf("xclip -t %s -o: %v", typ, err)
		}
		return out
	}, func() string {
		out, _ := exec.Command("xclip", "-selection", "clipboard", "-t", "TARGETS", "-o").Output()
		return string(out)
	})
}

func TestWaylandImages(t *testing.T) {
	if os.Getenv("CBB_TEST_WAYLAND") == "" {
		t.Skip("set CBB_TEST_WAYLAND in a session with a data-control compositor and wl-clipboard")
	}
	w, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	testImages(t, w, func(typ string, data []byte) {
		// wl-copy forks a child that serves the selection; its output is
		// not captured, or the pipes would stay open.
		cmd := exec.Command("wl-copy", "--type", typ)
		cmd.Stdin = bytes.NewReader(data)
		if err := cmd.Run(); err != nil {
			t.Fatalf("wl-copy: %v", err)
		}
	}, func(typ string) []byte {
		out, err := exec.Command("wl-paste", "--no-newline", "--type", typ).Output()
		if err != nil {
			t.Errorf("wl-paste --type %s: %v", typ, err)
		}
		return out
	}, func() string {
		out, _ := exec.Command("wl-paste", "--list-types").Output()
		return string(out)
	})
}
