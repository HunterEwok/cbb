// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// rawContent writes a content's bytes by hand, padded to size, so that a
// test can break what Encode never would.
func rawContent(head [3]byte, text, manifest []byte, textLen, manifestLen int, size int) []byte {
	var b bytes.Buffer
	b.Write(head[:])
	binary.Write(&b, binary.BigEndian, uint32(textLen))
	b.Write(text)
	binary.Write(&b, binary.BigEndian, uint32(manifestLen))
	b.Write(manifest)
	out := b.Bytes()
	if len(out) < size {
		out = append(out, make([]byte, size-len(out))...)
	}
	return out[:size]
}

// The content's lengths, text and manifest are read as strictly as its
// head (TestContentIsReadStrictly).
func TestContentLengthsAreReadStrictly(t *testing.T) {
	text := [3]byte{1, byte(Text) + 1, byte(Copy)}
	media := [3]byte{1, byte(Media) + 1, byte(Copy)}
	manifest, err := manifestJSON(imageContent(10).Media)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContent(rawContent(media, nil, manifest, 0, len(manifest), 1<<10)); err != nil {
		t.Fatalf("a media content by hand: %v", err)
	}
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"a text longer than the content", rawContent(text, []byte("x"), nil, 5000, 0, 1<<10)},
		{"a text cut short by the padding's end", rawContent(text, nil, nil, 1020, 0, 1<<10)},
		{"a text over 1 MiB", rawContent(text, nil, nil, MaxText+1, 0, 2<<20)},
		{"a text that is not UTF-8", rawContent(text, []byte{0xff, 0xfe}, nil, 2, 0, 1<<10)},
		{"a manifest longer than the content", rawContent(text, []byte("x"), nil, 1, 5000, 1<<10)},
		{"a manifest cut short", rawContent(text, []byte("x"), nil, 1, 1010, 1<<10)},
		{"no room for the manifest's length", append([]byte{1, byte(Text) + 1, byte(Copy), 0, 0, 3, 0xf8}, bytes.Repeat([]byte("a"), 1017)...)},
		{"a text with a manifest", rawContent(text, []byte("x"), []byte("{}"), 1, 2, 1<<10)},
		{"a manifest that does not read", rawContent(media, nil, []byte("{"), 0, 1, 1<<10)},
		{"media with an empty text and no parts", rawContent(media, nil, []byte(`{"parts":[],"size":0}`), 0, 21, 1<<10)},
		{"a secret with no text", rawContent([3]byte{1, byte(Secret) + 1, byte(Copy)}, nil, nil, 0, 0, 1<<10)},
	} {
		if _, err := DecodeContent(c.b); err == nil {
			t.Errorf("%s is taken", c.name)
		}
	}
}

// A receiver refuses each part of a sealed copy that breaks its rules,
// before it opens anything.
func TestSealedCopiesAreCheckedFirst(t *testing.T) {
	alice, bob := newDevice(t), newDevice(t)
	good := sealFor(t, alice, []testDevice{alice, bob}, textContent("hello"), nil, NewKey())
	if err := good.Validate(); err != nil {
		t.Fatalf("a good copy: %v", err)
	}
	other := newDevice(t)
	for _, c := range []struct {
		name   string
		change func(s *Sealed)
	}{
		{"a copy in the open", func(s *Sealed) { s.OpenText = []byte(`"hi"`) }},
		{"an open kind", func(s *Sealed) { s.OpenKind = []byte(`"text"`) }},
		{"an open way", func(s *Sealed) { s.OpenVia = []byte(`"copy"`) }},
		{"open media", func(s *Sealed) { s.OpenMedia = []byte(`{}`) }},
		{"a bad event ID", func(s *Sealed) { s.ID = "x" }},
		{"a bad origin", func(s *Sealed) { s.Origin = strings.Repeat("g", 32) }},
		{"no time", func(s *Sealed) { s.Time.Wall = 0; s.Time.Logical = 0 }},
		{"a negative age", func(s *Sealed) { s.Age = -1 }},
		{"a certificate that does not read", func(s *Sealed) { s.Cert = []byte{1, 2, 3} }},
		{"another device's certificate", func(s *Sealed) { s.Cert = other.cert.Raw }},
		{"an issuer that does not read", func(s *Sealed) { s.Issuer = []byte{1, 2, 3} }},
		{"no readers", func(s *Sealed) { s.Wraps = nil }},
		{"too many readers", func(s *Sealed) { s.Wraps = make([]Wrap, MaxReaders+1) }},
		{"a wrap of the wrong size", func(s *Sealed) { s.Wraps[0].Key = s.Wraps[0].Key[:10] }},
		{"a wrap for no device", func(s *Sealed) { s.Wraps[0].To = "x" }},
		{"wraps out of order", func(s *Sealed) { s.Wraps[0], s.Wraps[1] = s.Wraps[1], s.Wraps[0] }},
		{"a payload of no step", func(s *Sealed) { s.Payload = s.Payload[:100] }},
		{"a payload and its hash", func(s *Sealed) { s.PayloadSHA256 = make([]byte, 32) }},
		{"neither payload nor hash", func(s *Sealed) { s.Payload = nil }},
		{"a blob of part of a segment", func(s *Sealed) { s.Blob = &Blob{Size: 5, SHA256: make([]byte, 32)} }},
		{"a blob without a hash", func(s *Sealed) { s.Blob = &Blob{Size: SealedSegment} }},
		{"no signature", func(s *Sealed) { s.Sig = nil }},
	} {
		s := *good
		s.Wraps = append([]Wrap(nil), good.Wraps...)
		c.change(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s is taken", c.name)
		}
	}
}
