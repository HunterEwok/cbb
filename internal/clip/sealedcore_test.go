// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
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
	// A copy changed on the way does not open in the core.
	s := sealFor(t, a, []testDevice{b}, textContent("changed"), nil, NewKey())
	s.Payload[0] ^= 1
	if _, _, err := s.Open(b.id, b.secret); err == nil {
		t.Error("the core opens a changed copy")
	}
}
