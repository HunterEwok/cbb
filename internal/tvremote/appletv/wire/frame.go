// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package wire

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// A frame of the Companion protocol: its type, a 3-byte big-endian length,
// and the payload, which after pair-verify is sealed with ChaCha20-Poly1305
// under the frame's header, with a counter as the nonce.

// The frame types the remote uses.
const (
	FramePSStart = 3 // pair-setup, the first message
	FramePSNext  = 4 // pair-setup, the rest and every answer
	FramePVStart = 5 // pair-verify, the first message
	FramePVNext  = 6 // pair-verify, the rest and every answer
	FrameUOPACK  = 7 // OPACK in the clear
	FrameEOPACK  = 8 // OPACK, sealed
	FramePOPACK  = 9
)

// MaxFrame bounds a frame's payload.
const MaxFrame = 1 << 20

// Conn is a connection that reads and writes frames.
type Conn struct {
	net.Conn

	mu       sync.Mutex // guards writes
	out, in  cipher.AEAD
	outCount uint64
	inCount  uint64
}

// NewConn wraps c.
func NewConn(c net.Conn) *Conn { return &Conn{Conn: c} }

// Encrypt seals the frames from now on: out the key this side writes
// with, in the one it reads with.
func (c *Conn) Encrypt(out, in []byte) error {
	o, err := chacha20poly1305.New(out)
	if err != nil {
		return err
	}
	i, err := chacha20poly1305.New(in)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.out, c.in = o, i
	c.mu.Unlock()
	return nil
}

// counterNonce is a frame's nonce: the counter, little-endian, in 12 bytes.
func counterNonce(n uint64) []byte {
	b := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(b, n)
	return b
}

// WriteFrame writes one frame.
func (c *Conn) WriteFrame(typ byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(payload)
	if c.out != nil && n > 0 {
		n += c.out.Overhead()
	}
	if n > MaxFrame {
		return fmt.Errorf("a frame of %d bytes is too long", n)
	}
	b := []byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}
	if c.out != nil && len(payload) > 0 {
		b = c.out.Seal(b, counterNonce(c.outCount), payload, b[:4])
		c.outCount++
	} else {
		b = append(b, payload...)
	}
	_, err := c.Write(b)
	return err
}

// ErrSeal is a sealed frame that does not open.
var ErrSeal = errors.New("a frame does not decrypt")

// ReadFrame reads one frame.
func (c *Conn) ReadFrame() (typ byte, payload []byte, err error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if n > MaxFrame {
		return 0, nil, fmt.Errorf("a frame of %d bytes is too long", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		return 0, nil, err
	}
	if c.in != nil && n > 0 {
		p, err := c.in.Open(b[:0], counterNonce(c.inCount), b, h[:])
		if err != nil {
			return 0, nil, ErrSeal
		}
		c.inCount++
		b = p
	}
	return h[0], b, nil
}

// WriteOPACK writes m as an OPACK frame.
func (c *Conn) WriteOPACK(typ byte, m map[string]any) error {
	b, err := Pack(m)
	if err != nil {
		return err
	}
	return c.WriteFrame(typ, b)
}

// ReadOPACK reads a frame that holds an OPACK map.
func (c *Conn) ReadOPACK() (typ byte, m map[string]any, err error) {
	typ, b, err := c.ReadFrame()
	if err != nil {
		return 0, nil, err
	}
	v, err := Unpack(b)
	if err != nil {
		return 0, nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return 0, nil, fmt.Errorf("%w: a frame holds %T, not a map", ErrOPACK, v)
	}
	return typ, m, nil
}

// labelNonce is a pairing message's nonce: four zero bytes and its
// 8-byte label, as "PS-Msg05".
func labelNonce(label string) []byte {
	return append(make([]byte, 4), label...)
}

// Seal seals a pairing message's data with its label as the nonce.
func Seal(key []byte, label string, data []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, labelNonce(label), data, nil), nil
}

// Open opens what Seal sealed.
func Open(key []byte, label string, data []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	b, err := a.Open(nil, labelNonce(label), data, nil)
	if err != nil {
		return nil, ErrSeal
	}
	return b, nil
}

// Int reads an OPACK integer from a message, if it is one.
func Int(m map[string]any, key string) (int64, bool) {
	v, ok := m[key].(int64)
	return v, ok
}
