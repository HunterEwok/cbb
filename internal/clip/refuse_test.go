// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestSealedRefusals breaks one rule of a good copy at a time: Validate
// refuses each.
func TestSealedRefusals(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	good := sealFor(t, a, []testDevice{a, b}, textContent("hello"), nil, NewKey())
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		break_ func(s *Sealed)
		want   string
	}{
		{"id", func(s *Sealed) { s.ID = "x" }, "event ID"},
		{"origin", func(s *Sealed) { s.Origin = "x" }, "origin"},
		{"time", func(s *Sealed) { s.Time.Wall = 0; s.Time.Logical = 0 }, "timestamp"},
		{"age", func(s *Sealed) { s.Age = -1 }, "negative"},
		{"cert", func(s *Sealed) { s.Cert = []byte{1, 2, 3} }, "certificate"},
		{"cert of another", func(s *Sealed) { s.Cert = b.cert.Raw }, "not of its origin"},
		{"issuer", func(s *Sealed) { s.Issuer = []byte{1, 2, 3} }, "issuer"},
		{"no wraps", func(s *Sealed) { s.Wraps = nil }, "readers"},
		{"too many wraps", func(s *Sealed) { s.Wraps = make([]Wrap, MaxReaders+1) }, "readers"},
		{"wrap to", func(s *Sealed) { s.Wraps[0].To = "x" }, "wrap"},
		{"wrap size", func(s *Sealed) { s.Wraps[0].Key = s.Wraps[0].Key[1:] }, "wrap"},
		{"wraps order", func(s *Sealed) { s.Wraps[0], s.Wraps[1] = s.Wraps[1], s.Wraps[0] }, "sorted"},
		{"payload size", func(s *Sealed) { s.Payload = s.Payload[1:] }, "padded"},
		{"payload and hash", func(s *Sealed) { s.PayloadSHA256 = make([]byte, 32) }, "neither"},
		{"neither", func(s *Sealed) { s.Payload = nil }, "neither"},
		{"blob size", func(s *Sealed) { s.Blob = &Blob{Size: 1, SHA256: make([]byte, 32)} }, "blob"},
		{"blob hash", func(s *Sealed) { s.Blob = &Blob{Size: SealedSegment} }, "blob"},
		{"unsigned", func(s *Sealed) { s.Sig = nil }, "not signed"},
	}
	for _, c := range cases {
		s := *good
		s.Wraps = append([]Wrap(nil), good.Wraps...)
		c.break_(&s)
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// A copy whose payload was changed after sealing does not open.
	s := *good
	s.Payload = bytes.Clone(good.Payload)
	s.Payload[0] ^= 1
	if _, _, err := s.Open(a.id, a.secret); err == nil {
		t.Error("a changed payload opens")
	}
}

// TestSealCopyArguments refuses readers and keys out of their bounds.
func TestSealCopyArguments(t *testing.T) {
	a := newDevice(t)
	if _, err := SealCopy(NewID(), a.id, copyTime, a.cert.Raw, nil, nil, textContent("x"), nil, NewKey(), a.key); err == nil {
		t.Error("a copy for no reader")
	}
	if _, err := SealCopy(NewID(), a.id, copyTime, a.cert.Raw, nil, make([]Reader, MaxReaders+1), textContent("x"), nil, NewKey(), a.key); err == nil {
		t.Error("a copy for too many readers")
	}
	if _, err := SealCopy(NewID(), a.id, copyTime, a.cert.Raw, nil, readersOf(a), textContent("x"), nil, []byte{1}, a.key); err == nil {
		t.Error("a copy with a short key")
	}
	if _, err := SealCopy(NewID(), a.id, copyTime, a.cert.Raw, nil, []Reader{{a.id, []byte{1}}}, textContent("x"), nil, NewKey(), a.key); err == nil {
		t.Error("a copy for a reader with a bad key")
	}
	if _, err := SealCopy(NewID(), a.id, copyTime, a.cert.Raw, nil, readersOf(a), Content{Kind: Secret, Via: Copy}, nil, NewKey(), a.key); err == nil {
		t.Error("a secret with no text")
	}
	if _, err := (Content{Kind: Text, Via: Copy, Text: strings.Repeat("x", MaxText)}).Encode(); err != nil {
		t.Errorf("the largest text: %v", err)
	}
}

// content builds a Content's bytes by hand, padded to size.
func content(size int, version, kind, via byte, text, manifest []byte, textLen int) []byte {
	var b bytes.Buffer
	b.Write([]byte{version, kind, via})
	if textLen < 0 {
		textLen = len(text)
	}
	b.Write(binary.BigEndian.AppendUint32(nil, uint32(textLen)))
	b.Write(text)
	if manifest != nil {
		b.Write(binary.BigEndian.AppendUint32(nil, uint32(len(manifest))))
		b.Write(manifest)
	}
	return append(b.Bytes(), make([]byte, size-b.Len())...)
}

// TestDecodeContentRefusals feeds DecodeContent bytes that break its rules.
func TestDecodeContentRefusals(t *testing.T) {
	good := content(1<<10, 1, 1, 0, []byte("hi"), []byte{}, -1)
	if c, err := DecodeContent(good); err != nil || c.Text != "hi" {
		t.Fatalf("a good content: %+v, %v", c, err)
	}
	big := make([]byte, 2<<20)
	copy(big, []byte{1, 1, 0})
	binary.BigEndian.PutUint32(big[3:], MaxText+1)
	cases := []struct {
		name string
		b    []byte
		want string
	}{
		{"size", make([]byte, 100), "size"},
		{"version", content(1<<10, 2, 1, 0, nil, []byte{}, -1), "version"},
		{"kind", content(1<<10, 1, 9, 0, nil, []byte{}, -1), "kind"},
		{"via", content(1<<10, 1, 1, 99, nil, []byte{}, -1), "way"},
		{"text length past the end", content(1<<10, 1, 1, 0, nil, nil, 5000), "cut short"},
		{"no manifest length", content(1<<10, 1, 1, 0, nil, nil, 1015), "cut short"},
		{"text too large", big, "1 MiB"},
		{"not UTF-8", content(1<<10, 1, 1, 0, []byte{0xff, 0xfe}, []byte{}, -1), "UTF-8"},
		{"manifest on text", content(1<<10, 1, 1, 0, []byte("hi"), []byte("{}"), -1), "has a manifest"},
		{"bad manifest", content(1<<10, 1, 3, 0, nil, []byte("{"), -1), "manifest"},
		{"padding", append(content(1<<10, 1, 1, 0, nil, []byte{}, -1)[:1023], 1), "padding"},
		{"past its step", content(4<<10, 1, 1, 0, []byte("hi"), []byte{}, -1), "past its step"},
		{"empty secret", content(1<<10, 1, 2, 0, nil, []byte{}, -1), "empty"},
	}
	for _, c := range cases {
		_, err := DecodeContent(c.b)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
