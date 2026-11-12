// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
)

// sentPart is a part of a test copy with its bytes.
type sentPart struct {
	control.Part
	data []byte
}

func file(path string, data []byte) sentPart {
	return sentPart{Part: control.Part{Path: path, Size: int64(len(data))}, data: data}
}

// copyMedia sends a copy as cbb copy FILE does.
func (s *testService) copyMedia(t *testing.T, text string, parts ...sentPart) error {
	t.Helper()
	c := s.dial(t)
	defer c.Close()
	if err := c.Send(&control.Message{Header: control.Header{Op: control.OpCopyMedia}, Payload: []byte(text)}); err != nil {
		t.Fatal(err)
	}
	for _, p := range parts {
		if err := c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Part: &p.Part}}); err != nil {
			break
		}
		for b := p.data; len(b) > 0; {
			n := min(len(b), 1<<20)
			if err := c.Send(&control.Message{Header: control.Header{Op: control.OpData}, Payload: b[:n]}); err != nil {
				break
			}
			b = b[n:]
		}
	}
	c.Send(&control.Message{Header: control.Header{Op: control.OpPart, Done: true}})
	_, err := c.Receive()
	return err
}

// pasteMedia asks for the clipboard's images or files as cbb paste -o
// does.
func (s *testService) pasteMedia(t *testing.T) (string, []sentPart, error) {
	t.Helper()
	c := s.dial(t)
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPasteMedia}})
	if err != nil {
		return "", nil, err
	}
	text := string(m.Payload)
	var parts []sentPart
	for {
		m, err := c.Receive()
		if err != nil {
			return "", nil, err
		}
		switch {
		case m.Done:
			return text, parts, nil
		case m.Part != nil:
			parts = append(parts, sentPart{Part: *m.Part})
		case len(parts) > 0:
			parts[len(parts)-1].data = append(parts[len(parts)-1].data, m.Payload...)
		default:
			t.Fatalf("bytes before a part: %+v", m.Header)
		}
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// TestMedia: files copied on one member reach the other, which fetches
// them when cbb paste -o asks in mode own, or by itself once its mode
// takes the group's copies; a copy over its limit is not fetched.
func TestMedia(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "beta connected", func() bool { return len(b.status(t).Peers) == 1 })
	if _, err := b.do(t, control.Header{Op: control.OpSync, On: control.Bool(false)}, ""); err != nil {
		t.Fatal(err)
	}

	big := randomBytes(3<<20 + 5)
	sent := []sentPart{
		{Part: control.Part{Path: "photos", Dir: true}},
		file("photos/one.jpg", big),
		file("photos/empty.txt", nil),
		file("notes.txt", []byte("hello")),
	}
	if err := a.copyMedia(t, "photos, notes.txt", sent...); err != nil {
		t.Fatal(err)
	}
	if got := a.paste(t); got != "photos, notes.txt" {
		t.Errorf("paste on alpha = %q, want the text alternative", got)
	}
	check := func(s *testService) {
		t.Helper()
		text, got, err := s.pasteMedia(t)
		if err != nil {
			t.Fatalf("paste -o on %s: %v", s.name, err)
		}
		if text != "photos, notes.txt" || len(got) != len(sent) {
			t.Fatalf("paste -o on %s: %q, %d parts", s.name, text, len(got))
		}
		for i, p := range got {
			if p.Part != sent[i].Part || !bytes.Equal(p.data, sent[i].data) {
				t.Errorf("part %d on %s: %+v with %d bytes, want %+v", i, s.name, p.Part, len(p.data), sent[i].Part)
			}
		}
	}
	check(a)
	// Beta has sync off: paste -o fetches the group's copy.
	waitFor(t, "beta has the copy", func() bool { return b.paste(t) == "photos, notes.txt" })
	check(b)

	// With sync on beta fetches by itself.
	if _, err := b.do(t, control.Header{Op: control.OpSync, On: control.Bool(true)}, ""); err != nil {
		t.Fatal(err)
	}
	// A watcher whose clipboard takes images gets the image once it has
	// arrived; one without gets nothing, as it has no text.
	iw := b.dial(t)
	defer iw.Close()
	if _, err := iw.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Images: true}}); err != nil {
		t.Fatal(err)
	}
	png := sentPart{Part: control.Part{Type: clip.TypePNG, Size: 1 << 20}, data: randomBytes(1 << 20)}
	if err := a.copyMedia(t, "", png); err != nil {
		t.Fatal(err)
	}
	iw.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		m, err := iw.Receive()
		if err != nil {
			t.Fatalf("the image watcher got no image: %v", err)
		}
		if m.Op == control.OpWrite && m.Kind == control.KindMedia {
			break
		}
		if string(m.Payload) != "photos, notes.txt" { // the earlier copy, which the watch started with
			t.Fatalf("the image watcher got %s %s %q", m.Op, m.Kind, m.Payload)
		}
	}
	sum := sha256.Sum256(png.data)
	waitFor(t, "beta fetched the image", func() bool {
		if rustService() != "" {
			// The Rust service keeps the sealed blob, under its own hash.
			es, _ := os.ReadDir(filepath.Join(b.dir, contentDir))
			for _, e := range es {
				if fi, err := e.Info(); err == nil && !strings.HasSuffix(e.Name(), ".part") && fi.Size() >= int64(len(png.data)) {
					return true
				}
			}
			return false
		}
		_, err := os.Stat(filepath.Join(b.dir, contentDir, hex.EncodeToString(sum[:])))
		return err == nil
	})
	if _, got, err := b.pasteMedia(t); err != nil || len(got) != 1 || !bytes.Equal(got[0].data, png.data) {
		t.Errorf("the image on beta: %v", err)
	}
	if _, err := b.do(t, control.Header{Op: control.OpPaste}, ""); err == nil || !strings.Contains(err.Error(), "paste -o") {
		t.Errorf("paste of an image without a text: %v", err)
	}

	// A copy over beta's limit.
	for _, bad := range [][2]string{{"max-copy", "512KiB"}, {"max-copy", "2GiB"}, {"max-copy-away", "200MiB"}, {"colour", "red"}, {"max-copy", "lots"}} {
		if _, err := b.do(t, control.Header{Op: control.OpConfig, Name: bad[0], Value: bad[1]}, ""); err == nil {
			t.Errorf("config %s %s succeeded", bad[0], bad[1])
		}
	}
	m, err := b.do(t, control.Header{Op: control.OpConfig, Name: "max-copy", Value: "2MiB"}, "")
	if err != nil || m.Status.Media.MaxCopy != 2<<20 || m.Status.Media.MaxCopyAway != 2<<20 {
		t.Fatalf("config max-copy 2MiB: %+v, %v", m, err)
	}
	if err := a.copyMedia(t, "large", file("large.bin", randomBytes(3<<20))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta refuses the large copy", func() bool {
		return strings.Contains(b.status(t).Media.Failed, "over this device's limit of 2 MiB")
	})
	if _, _, err := b.pasteMedia(t); err == nil {
		t.Error("paste -o of a copy over the limit succeeded")
	}
	if err := b.copyMedia(t, "", file("large.bin", randomBytes(3<<20))); err == nil || !strings.Contains(err.Error(), "limit of 2 MiB") {
		t.Errorf("copying over the limit: %v", err)
	}
	// The setting stays.
	b.stop()
	b = restartService(t, &h, b)
	if st := b.status(t); st.Media == nil || st.Media.MaxCopy != 2<<20 {
		t.Errorf("after a restart: %+v", st.Media)
	}
	if entries, _ := os.ReadDir(filepath.Join(b.dir, contentDir)); len(entries) != 0 {
		t.Errorf("the cache after a restart holds %d files", len(entries))
	}
}
