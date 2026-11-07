// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"github.com/HunterEwok/cbb/internal/core"
)

// TestCoreAndGoSealAlike seals copies through the core and opens them with
// Go's code, and the other way round, text and media, in a build that links
// the core (go test -tags cbbwasm, as CI's job "go test with the Rust
// core"): the release builds seal and open through the core, the members
// built without it with Go's code, and both must read each other.
func TestCoreAndGoSealAlike(t *testing.T) {
	if !core.Linked() {
		t.Skip("the core is not linked (go test -tags cbbwasm)")
	}
	a, b := newDevice(t), newDevice(t)
	media := &Manifest{Parts: []Part{{Type: TypePNG, Size: 3, SHA256: make([]byte, 32)}}, Size: 3}
	blob := &Blob{Size: SealedSegment, SHA256: make([]byte, 32)}
	contents := []struct {
		c    Content
		blob *Blob
	}{
		{textContent("from the core to Go"), nil},
		{Content{Kind: Secret, Via: Phone, Text: "a secret"}, nil},
		{Content{Kind: Media, Via: Copy, Text: "an image", Media: media}, blob},
	}
	for _, x := range contents {
		key := NewKey()
		readers := readersOf(a, b)
		s, toSign, err := sealInCore(NewID(), a.id, copyTime, a.cert.Raw, nil, readers, x.c, x.blob, key)
		if err != nil {
			t.Fatalf("%q: the core seals: %v", x.c.Text, err)
		}
		g, goSign, err := sealInGo(s.ID, a.id, copyTime, a.cert.Raw, nil, readers, x.c, x.blob, key)
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(goSign)
		if g.Sig, err = a.key.Sign(rand.Reader, d[:], crypto.SHA256); err != nil {
			t.Fatal(err)
		}
		if string(toSign) == string(goSign) {
			t.Errorf("%q: the core's copy and Go's sign the same bytes: their wraps should differ", x.c.Text)
		}
		if string(toSign) != string(s.ToSign()) {
			t.Errorf("%q: the core's to_sign is not Go's reading of its copy", x.c.Text)
		}
		for _, d := range []testDevice{a, b} {
			i := 0
			if s.Wraps[1].To == d.id {
				i = 1
			}
			got, k, err := s.openInGo(i, d.secret)
			if err != nil || got.Text != x.c.Text || got.Kind != x.c.Kind || string(k) != string(key) {
				t.Errorf("%q: Go opens the core's copy: %+v, %v", x.c.Text, got, err)
			}
			got, k, err = openInCore(g, d.id, d.secret)
			if err != nil || got.Text != x.c.Text || got.Kind != x.c.Kind || got.Via != x.c.Via || string(k) != string(key) {
				t.Errorf("%q: the core opens Go's copy: %+v, %v", x.c.Text, got, err)
			}
			if (got.Media == nil) != (x.c.Media == nil) {
				t.Errorf("%q: the manifest is lost", x.c.Text)
			}
		}
	}
	// The core seals with an issuer as given, and refuses a reader whose
	// seal is no key.
	if s, _, err := sealInCore(NewID(), a.id, copyTime, a.cert.Raw, a.cert.Raw, readersOf(a, b), textContent("issued"), nil, NewKey()); err != nil || string(s.Issuer) != string(a.cert.Raw) {
		t.Errorf("the core seals with an issuer: %v", err)
	}
	bad := readersOf(a, b)
	bad[1].Seal = []byte("no key")
	if _, _, err := sealInCore(NewID(), a.id, copyTime, a.cert.Raw, nil, bad, textContent("x"), nil, NewKey()); err == nil {
		t.Error("the core seals to a reader whose seal is no key")
	}
	// A copy changed on the way does not open in the core.
	s := sealFor(t, a, []testDevice{b}, textContent("changed"), nil, NewKey())
	s.Payload[0] ^= 1
	if _, _, err := s.Open(b.id, b.secret); err == nil {
		t.Error("the core opens a changed copy")
	}
}

// TestBlobRefusals checks what a blob's sealing and opening refuse: a key
// that is not 32 bytes, a segment too large or of the wrong size, sizes
// that do not fit, a short source, a writer that fails and a padding that
// is not zeros.
func TestBlobRefusals(t *testing.T) {
	key := NewKey()
	if _, err := SealSegment(key[:31], 0, true, nil); err == nil {
		t.Error("a segment sealed with a short key")
	}
	if _, err := SealSegment(key, 0, true, make([]byte, Segment+1)); err == nil {
		t.Error("a segment larger than Segment sealed")
	}
	if _, err := OpenSegment(key, 0, true, make([]byte, SealedSegment-1)); err == nil {
		t.Error("a short segment opened")
	}
	var sink bytes.Buffer
	for _, n := range []int64{0, -1, MaxMedia + 1} {
		if _, err := SealBlob(key, bytes.NewReader(nil), n, &sink); err == nil {
			t.Errorf("a blob of %d bytes sealed", n)
		}
	}
	if _, err := SealBlob(key, bytes.NewReader([]byte("ab")), 3, &sink); err == nil {
		t.Error("a blob sealed from a source shorter than it")
	}
	if _, err := SealBlob(key, bytes.NewReader([]byte("abc")), 3, failWriter{}); err == nil {
		t.Error("a blob sealed into a writer that fails")
	}
	sink.Reset()
	b, err := SealBlob(key, bytes.NewReader([]byte("abc")), 3, &sink)
	if err != nil {
		t.Fatal(err)
	}
	sealed := sink.Bytes()
	if err := OpenBlob(key, bytes.NewReader(sealed), nil, 3, io.Discard); err == nil {
		t.Error("a blob opened without its record")
	}
	if err := OpenBlob(key, bytes.NewReader(sealed), b, 3, failWriter{}); err == nil {
		t.Error("a blob opened into a writer that fails")
	}
	if err := OpenBlob(key, bytes.NewReader(sealed[:10]), b, 3, io.Discard); err == nil {
		t.Error("a short blob opened")
	}
	// Two bytes claimed of three: the third is not padding.
	if err := OpenBlob(key, bytes.NewReader(sealed), &Blob{Size: BlobSize(2)}, 2, io.Discard); err == nil {
		t.Error("a blob whose padding is not zeros opened")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("the disk is full") }
