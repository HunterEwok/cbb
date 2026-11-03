// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package wire

import (
	"errors"
	"fmt"
)

// TLV8 is HomeKit's pairing encoding, which the Companion protocol's
// pairing carries in "_pd": a type byte, a length byte and up to 255 bytes
// of value; a longer value is split into items of the same type in a row.

// The TLV8 types of the pairing.
const (
	TLVMethod    = 0x00
	TLVID        = 0x01
	TLVSalt      = 0x02
	TLVPublicKey = 0x03
	TLVProof     = 0x04
	TLVEncrypted = 0x05
	TLVState     = 0x06
	TLVError     = 0x07
	TLVBackOff   = 0x08
	TLVSignature = 0x0A
	TLVName      = 0x11
)

// The pairing's error codes (TLVError).
const (
	TLVErrUnknown        = 0x01
	TLVErrAuthentication = 0x02
	TLVErrBackOff        = 0x03
	TLVErrMaxPeers       = 0x04
	TLVErrMaxTries       = 0x05
	TLVErrUnavailable    = 0x06
	TLVErrBusy           = 0x07
)

// TLV is TLV8 items in order.
type TLV []TLVItem

// TLVItem is one item, its value whole.
type TLVItem struct {
	Type  byte
	Value []byte
}

// Encode writes the items, splitting the long values.
func (t TLV) Encode() []byte {
	var b []byte
	for _, it := range t {
		v := it.Value
		for {
			n := min(len(v), 255)
			b = append(b, it.Type, byte(n))
			b = append(b, v[:n]...)
			v = v[n:]
			if len(v) == 0 {
				break
			}
		}
	}
	return b
}

// ErrTLV is pairing data that is not TLV8.
var ErrTLV = errors.New("the pairing data is not TLV8")

// DecodeTLV reads TLV8 into a map of type to value, joining the split
// values.
func DecodeTLV(b []byte) (map[byte][]byte, error) {
	m := map[byte][]byte{}
	last := -1
	for len(b) > 0 {
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return nil, fmt.Errorf("%w: cut short", ErrTLV)
		}
		t, v := b[0], b[2:2+int(b[1])]
		if _, ok := m[t]; ok && int(t) != last {
			return nil, fmt.Errorf("%w: type %#x twice", ErrTLV, t)
		}
		m[t] = append(m[t], v...)
		last = int(t)
		b = b[2+len(v):]
	}
	return m, nil
}
