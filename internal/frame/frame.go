// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package frame is the one framing of every channel between devices and
// servers (docs/protocol.md, Conventions, "Frames"): a 4-byte big-endian
// length and that many bytes of one JSON object. The member protocol adds
// its binary chunk frames on top (member/src/content.rs); pairing, the forwarder
// and the relay use these frames as they are.
package frame

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Encode returns v as a frame. Its JSON is written without HTML escaping,
// which would make texts that hold <, > or & longer.
func Encode(v any, max int) ([]byte, error) {
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 0})
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	data := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	n := len(data) - 4
	if n > max {
		return nil, fmt.Errorf("frame: a message of %d bytes is over %d", n, max)
	}
	binary.BigEndian.PutUint32(data, uint32(n))
	return data, nil
}

// Write writes v to w as one frame of at most max bytes of JSON, in one
// write.
func Write(w io.Writer, v any, max int) error {
	data, err := Encode(v, max)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ReadBytes reads one frame's JSON from r: at most max bytes, and one JSON
// object. It reads exactly the frame and nothing after it, so another
// protocol may follow on r.
func ReadBytes(r io.Reader, max int) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || uint64(size) > uint64(max) {
		return nil, fmt.Errorf("frame: a frame of %d bytes, more than %d or none", size, max)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	if t := bytes.TrimLeft(data, " \t\r\n"); len(t) == 0 || t[0] != '{' {
		return nil, errors.New("frame: a frame that is not a JSON object")
	}
	return data, nil
}

// Read reads one frame from r into v; see ReadBytes.
func Read(r io.Reader, v any, max int) error {
	data, err := ReadBytes(r, max)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// An Encoder writes frames of at most max bytes of JSON to w, like
// json.Encoder writes values.
type Encoder struct {
	w   io.Writer
	max int
}

// NewEncoder returns an Encoder that writes to w.
func NewEncoder(w io.Writer, max int) *Encoder { return &Encoder{w, max} }

// Encode writes v as one frame.
func (e *Encoder) Encode(v any) error { return Write(e.w, v, e.max) }

// A Decoder reads frames of at most max bytes of JSON from r, like
// json.Decoder reads values; it never reads past the frame it decodes.
type Decoder struct {
	r   io.Reader
	max int
}

// NewDecoder returns a Decoder that reads from r.
func NewDecoder(r io.Reader, max int) *Decoder { return &Decoder{r, max} }

// Decode reads one frame into v.
func (d *Decoder) Decode(v any) error { return Read(d.r, v, d.max) }
