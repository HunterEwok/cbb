// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/connector"
)

func TestHTMLText(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want string
	}{
		{[]byte("<b>hi</b>"), "<b>hi</b>"},
		{[]byte("\xef\xbb\xbf<b>hi</b>\x00"), "<b>hi</b>"},
		{[]byte{0xff, 0xfe, '<', 0, 'b', 0, '>', 0, 0xe9, 0, 0, 0}, "<b>é"},
		{[]byte{0xfe, 0xff, 0, '<', 0, 'i', 0, '>'}, "<i>"},
	} {
		if got := htmlText(c.in); got != c.want {
			t.Errorf("htmlText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// htmlBoard is a board under test that takes formatted text.
type htmlBoard interface {
	connector.Board
	connector.HTMLBoard
}

// testHTML writes formatted text on one board and reads it on another, as
// a browser's copy, pastes both its types with a tool, and checks that a
// tool's plain text comes without formatted text.
func testHTML(t *testing.T, a, b htmlBoard, paste func(typ string) []byte, copyText func(string)) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Larger than one piece of X11's INCR.
	html := "<p>" + strings.Repeat("<b>bold</b> and <i>italic</i> ", 8000) + "</p>"
	text := strings.Repeat("bold and italic ", 8000)
	if err := a.WriteHTML(html, text); err != nil {
		t.Fatal(err)
	}
	it, ok, err := b.Next(ctx)
	if err != nil || !ok || it.Text != text || it.HTML != html {
		t.Fatalf("Next after formatted text = %v, %v, text of %d bytes, HTML of %d bytes", ok, err, len(it.Text), len(it.HTML))
	}
	if got := string(paste(clip.TypeHTML)); got != html {
		t.Errorf("pasted %d bytes of HTML, want %d", len(got), len(html))
	}
	if got := string(paste("text/plain")); got != text {
		t.Errorf("pasted %d bytes of text, want %d", len(got), len(text))
	}
	copyText("plain again")
	it, ok, err = b.Next(ctx)
	if err != nil || !ok || it.Text != "plain again" || it.HTML != "" {
		t.Errorf("Next after a plain text = %q, %q, %v, %v", it.Text, it.HTML, ok, err)
	}
}

func TestX11HTML(t *testing.T) {
	if os.Getenv("CBB_TEST_X11") == "" {
		t.Skip("set CBB_TEST_X11 with an X server in DISPLAY and xclip installed")
	}
	a, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenX11(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	testHTML(t, a, b, func(typ string) []byte {
		out, err := exec.Command("xclip", "-selection", "clipboard", "-t", typ, "-o").Output()
		if err != nil {
			t.Errorf("xclip -t %s -o: %v", typ, err)
		}
		return out
	}, func(text string) {
		cmd := exec.Command("xclip", "-selection", "clipboard", "-i")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			t.Fatalf("xclip -i: %v", err)
		}
	})
}

func TestWaylandHTML(t *testing.T) {
	if os.Getenv("CBB_TEST_WAYLAND") == "" {
		t.Skip("set CBB_TEST_WAYLAND in a session with a data-control compositor and wl-clipboard")
	}
	a, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	testHTML(t, a, b, func(typ string) []byte {
		out, err := exec.Command("wl-paste", "--no-newline", "--type", typ).Output()
		if err != nil {
			t.Errorf("wl-paste --type %s: %v", typ, err)
		}
		return out
	}, func(text string) {
		cmd := exec.Command("wl-copy", "--type", "text/plain;charset=utf-8")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			t.Fatalf("wl-copy: %v", err)
		}
	})
}
