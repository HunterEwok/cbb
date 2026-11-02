// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package pivtest plays a YubiKey's PIV application for tests: retired
// slots with P-256 keys and their certificates, a PIN, command chaining, and
// long answers in parts (61xx) the way a card sends them.
package pivtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"
)

// Card is a card with the PIV application; it implements piv.Card.
type Card struct {
	mu sync.Mutex
	// Slots holds the retired slots' keys and certificates.
	Slots map[byte]Slot
	// PIN is the card's PIN, and Tries the attempts left.
	PIN   string
	Tries int
	// NoPIV makes the card refuse the PIV application, as a bank card.
	NoPIV              bool
	signed             int
	closed             bool
	selected, verified bool
	chain              []byte
	pending            []byte
}

// Slot is a key slot: its key, and the certificate stored for it, if any.
type Slot struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
}

// New returns a card whose slot holds key and cert, with PIN 123456.
func New(slot byte, key *ecdsa.PrivateKey, cert *x509.Certificate) *Card {
	return &Card{Slots: map[byte]Slot{slot: {key, cert}}, PIN: "123456", Tries: 3}
}

func (c *Card) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed, c.selected, c.verified = true, false, false
	return nil
}

// Connect opens the card again after Close, as a new connection.
func (c *Card) Connect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = false
}

// Closed tells whether the connection is closed.
func (c *Card) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Signed counts the signatures the card made.
func (c *Card) Signed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signed
}

// Slot returns the slot's key and certificate.
func (c *Card) Slot(slot byte) (Slot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.Slots[slot]
	return s, ok
}

// SetSlot puts a key and its certificate in slot.
func (c *Card) SetSlot(slot byte, s Slot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Slots[slot] = s
}

func sw(data []byte, w uint16) []byte { return append(append([]byte{}, data...), byte(w>>8), byte(w)) }

// Transmit answers one APDU.
func (c *Card) Transmit(apdu []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("pivtest: the card is closed")
	}
	if len(apdu) < 4 {
		return sw(nil, 0x6700), nil
	}
	cla, ins, p1, p2 := apdu[0], apdu[1], apdu[2], apdu[3]
	var data []byte
	if len(apdu) > 5 {
		n := int(apdu[4])
		if len(apdu) < 5+n {
			return sw(nil, 0x6700), nil
		}
		data = apdu[5 : 5+n]
	}
	if ins == 0xc0 {
		return c.send(nil), nil
	}
	if cla&0x10 != 0 {
		c.chain = append(c.chain, data...)
		return sw(nil, 0x9000), nil
	}
	data = append(c.chain, data...)
	c.chain = nil
	switch ins {
	case 0xa4:
		if c.NoPIV || !bytes.Equal(data, []byte{0xa0, 0x00, 0x00, 0x03, 0x08}) {
			return sw(nil, 0x6a82), nil
		}
		c.selected, c.verified = true, false
		return sw(nil, 0x9000), nil
	}
	if !c.selected {
		return sw(nil, 0x6d00), nil
	}
	switch ins {
	case 0xcb:
		if p1 != 0x3f || p2 != 0xff || len(data) != 5 || !bytes.Equal(data[:4], []byte{0x5c, 0x03, 0x5f, 0xc1}) || data[4] < 0x0d || data[4] > 0x20 {
			return sw(nil, 0x6a80), nil
		}
		s, ok := c.Slots[0x82+data[4]-0x0d]
		if !ok || s.Cert == nil {
			return sw(nil, 0x6a82), nil
		}
		obj := tlv(0x53, append(tlv(0x70, s.Cert.Raw), tlv(0x71, []byte{0})...))
		return c.send(obj), nil
	case 0x20:
		if p2 != 0x80 || len(data) != 8 {
			return sw(nil, 0x6a80), nil
		}
		if c.Tries == 0 {
			return sw(nil, 0x6983), nil
		}
		if !bytes.Equal(bytes.TrimRight(data, "\xff"), []byte(c.PIN)) {
			c.Tries--
			return sw(nil, 0x63c0|uint16(c.Tries)), nil
		}
		c.Tries, c.verified = 3, true
		return sw(nil, 0x9000), nil
	case 0x87:
		s, ok := c.Slots[p2]
		if p1 != 0x11 || !ok {
			return sw(nil, 0x6a86), nil
		}
		if !c.verified {
			return sw(nil, 0x6982), nil
		}
		in, err := value(data, 0x7c)
		if err != nil || len(in) != 4+32 || !bytes.Equal(in[:4], []byte{0x82, 0x00, 0x81, 0x20}) {
			return sw(nil, 0x6a80), nil
		}
		sig, err := ecdsa.SignASN1(rand.Reader, s.Key, in[4:])
		if err != nil {
			return sw(nil, 0x6f00), nil
		}
		c.signed++
		return c.send(tlv(0x7c, tlv(0x82, sig))), nil
	}
	return sw(nil, 0x6d00), nil
}

// send answers with data in parts of 100 bytes, as 61xx and GET RESPONSE
// pass them.
func (c *Card) send(data []byte) []byte {
	if data != nil {
		c.pending = data
	}
	part := c.pending
	if len(part) <= 100 {
		c.pending = nil
		return sw(part, 0x9000)
	}
	c.pending = part[100:]
	rest := len(c.pending)
	if rest > 0xff {
		rest = 0
	}
	return sw(part[:100], 0x6100|uint16(rest))
}

func tlv(tag byte, v []byte) []byte {
	out := []byte{tag}
	switch n := len(v); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, v...)
}

func value(b []byte, tag byte) ([]byte, error) {
	if len(b) < 2 || b[0] != tag || int(b[1]) != len(b)-2 {
		return nil, errors.New("pivtest: bad TLV")
	}
	return b[2:], nil
}
