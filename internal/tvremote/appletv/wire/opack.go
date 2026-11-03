// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"unicode/utf8"
)

// OPACK is Apple's compact encoding of the Companion protocol's messages:
// a tag byte, then the value. Pack writes nil, bool, the integers, float64,
// string, []byte, UUID, []any and map[string]any, with no references back
// to earlier objects; Unpack reads them and the references too. Unpacked
// integers are int64 (uint64 above its range), and a map's keys must be
// strings.

// UUID is OPACK's 16-byte UUID.
type UUID [16]byte

// ErrOPACK is a message that is not OPACK this package reads.
var ErrOPACK = errors.New("not a valid OPACK message")

// maxDepth bounds the nesting of arrays and maps a message may have.
const maxDepth = 16

// Pack encodes v.
func Pack(v any) ([]byte, error) {
	return pack(nil, v, 0)
}

func pack(b []byte, v any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("OPACK: nested deeper than %d", maxDepth)
	}
	switch x := v.(type) {
	case nil:
		return append(b, 0x04), nil
	case bool:
		if x {
			return append(b, 0x01), nil
		}
		return append(b, 0x02), nil
	case UUID:
		return append(append(b, 0x05), x[:]...), nil
	case int:
		return packInt(b, int64(x))
	case int64:
		return packInt(b, x)
	case uint32:
		return packInt(b, int64(x))
	case uint64:
		if x > math.MaxInt64 {
			return binary.LittleEndian.AppendUint64(append(b, 0x33), x), nil
		}
		return packInt(b, int64(x))
	case float64:
		return binary.LittleEndian.AppendUint64(append(b, 0x36), math.Float64bits(x)), nil
	case string:
		return packSized(b, 0x40, 0x60, []byte(x)), nil
	case []byte:
		return packSized(b, 0x70, 0x90, x), nil
	case []any:
		b = append(b, 0xD0+byte(min(len(x), 0xF)))
		var err error
		for _, e := range x {
			if b, err = pack(b, e, depth+1); err != nil {
				return nil, err
			}
		}
		if len(x) >= 0xF {
			b = append(b, 0x03)
		}
		return b, nil
	case map[string]any:
		b = append(b, 0xE0+byte(min(len(x), 0xF)))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var err error
		for _, k := range keys {
			b = packSized(b, 0x40, 0x60, []byte(k))
			if b, err = pack(b, x[k], depth+1); err != nil {
				return nil, err
			}
		}
		if len(x) >= 0xF {
			b = append(b, 0x03)
		}
		return b, nil
	}
	return nil, fmt.Errorf("OPACK: cannot pack %T", v)
}

func packInt(b []byte, x int64) ([]byte, error) {
	switch {
	case x < 0:
		return nil, errors.New("OPACK: negative integers are not packed")
	case x < 0x28:
		return append(b, byte(x)+8), nil
	case x <= math.MaxUint8:
		return append(b, 0x30, byte(x)), nil
	case x <= math.MaxUint16:
		return binary.LittleEndian.AppendUint16(append(b, 0x31), uint16(x)), nil
	case x <= math.MaxUint32:
		return binary.LittleEndian.AppendUint32(append(b, 0x32), uint32(x)), nil
	}
	return binary.LittleEndian.AppendUint64(append(b, 0x33), uint64(x)), nil
}

// packSized writes a string (base 0x40) or bytes (0x70): short ones carry
// their length in the tag, longer ones a little-endian length after it
// (four bytes long: 0x64 for a string, 0x93 for bytes).
func packSized(b []byte, base, long byte, v []byte) []byte {
	n := len(v)
	switch {
	case n <= 0x20:
		b = append(b, base+byte(n))
	case n <= math.MaxUint8:
		b = append(b, long+1, byte(n))
	case n <= math.MaxUint16:
		b = binary.LittleEndian.AppendUint16(append(b, long+2), uint16(n))
	case long == 0x60:
		b = binary.LittleEndian.AppendUint32(append(b, long+4), uint32(n))
	default:
		b = binary.LittleEndian.AppendUint32(append(b, long+3), uint32(n))
	}
	return append(b, v...)
}

// Unpack decodes one value and checks nothing follows it.
func Unpack(b []byte) (any, error) {
	d := decoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if len(d.b) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after the value", ErrOPACK, len(d.b))
	}
	return v, nil
}

type decoder struct {
	b    []byte
	refs []any // the values a later tag may refer back to
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || len(d.b) < n {
		return nil, fmt.Errorf("%w: cut short", ErrOPACK)
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v, nil
}

func (d *decoder) uint(n int) (uint64, error) {
	v, err := d.take(n)
	if err != nil {
		return 0, err
	}
	var x uint64
	for i := n - 1; i >= 0; i-- {
		x = x<<8 | uint64(v[i])
	}
	return x, nil
}

func (d *decoder) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested deeper than %d", ErrOPACK, maxDepth)
	}
	t, err := d.take(1)
	if err != nil {
		return nil, err
	}
	tag := t[0]
	var v any
	switch {
	case tag == 0x01:
		return true, nil
	case tag == 0x02:
		return false, nil
	case tag == 0x04:
		return nil, nil
	case tag == 0x05:
		u, err := d.take(16)
		if err != nil {
			return nil, err
		}
		v = UUID(u)
	case tag == 0x06: // an absolute time, read as its integer
		x, err := d.uint(8)
		if err != nil {
			return nil, err
		}
		v = integer(x)
	case tag >= 0x08 && tag <= 0x2F:
		return int64(tag - 8), nil
	case tag >= 0x30 && tag <= 0x33:
		x, err := d.uint(1 << (tag & 0xF))
		if err != nil {
			return nil, err
		}
		v = integer(x)
	case tag == 0x35:
		x, err := d.uint(4)
		if err != nil {
			return nil, err
		}
		v = float64(math.Float32frombits(uint32(x)))
	case tag == 0x36:
		x, err := d.uint(8)
		if err != nil {
			return nil, err
		}
		v = math.Float64frombits(x)
	case tag >= 0x40 && tag <= 0x64:
		s, err := d.sized(tag, 0x40, 0x60)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(s) {
			return nil, fmt.Errorf("%w: a string is not UTF-8", ErrOPACK)
		}
		v = string(s)
	case tag >= 0x70 && tag <= 0x94:
		s, err := d.sized(tag, 0x70, 0x90)
		if err != nil {
			return nil, err
		}
		v = slices.Clone(s)
	case tag >= 0xA0 && tag <= 0xC0:
		return d.ref(uint64(tag - 0xA0))
	case tag >= 0xC1 && tag <= 0xC4:
		i, err := d.uint(int(tag - 0xC0))
		if err != nil {
			return nil, err
		}
		return d.ref(i)
	case tag&0xF0 == 0xD0:
		var out []any
		err := d.items(tag, func() error {
			e, err := d.value(depth + 1)
			out = append(out, e)
			return err
		})
		return out, err
	case tag&0xF0 == 0xE0:
		out := map[string]any{}
		err := d.items(tag, func() error {
			k, err := d.value(depth + 1)
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok {
				return fmt.Errorf("%w: a key is %T, not a string", ErrOPACK, k)
			}
			e, err := d.value(depth + 1)
			out[key] = e
			return err
		})
		return out, err
	default:
		return nil, fmt.Errorf("%w: tag %#x", ErrOPACK, tag)
	}
	d.refs = append(d.refs, v)
	return v, nil
}

// integer is an unpacked integer: int64, or uint64 above its range.
func integer(x uint64) any {
	if x > math.MaxInt64 {
		return x
	}
	return int64(x)
}

// sized reads a string (short 0x40) or bytes (short 0x70): up to 32 bytes
// counted in the tag, or a little-endian length after the tag, of 1, 2, 3
// or 4 bytes for a string and 1, 2, 4 or 8 for bytes.
func (d *decoder) sized(tag, short, long byte) ([]byte, error) {
	if tag <= long {
		return d.take(int(tag - short))
	}
	w := int(tag - long)
	if short == 0x70 {
		w = 1 << (w - 1)
	}
	n, err := d.uint(w)
	if err != nil {
		return nil, err
	}
	if n > uint64(len(d.b)) {
		return nil, fmt.Errorf("%w: cut short", ErrOPACK)
	}
	return d.take(int(n))
}

func (d *decoder) ref(i uint64) (any, error) {
	if i >= uint64(len(d.refs)) {
		return nil, fmt.Errorf("%w: a reference to object %d of %d", ErrOPACK, i, len(d.refs))
	}
	return d.refs[i], nil
}

// items reads an array's or a map's entries: up to 14 counted in the tag,
// or any number ended by 0x03.
func (d *decoder) items(tag byte, item func() error) error {
	n := int(tag & 0xF)
	if n < 0xF {
		for range n {
			if err := item(); err != nil {
				return err
			}
		}
		return nil
	}
	for {
		if len(d.b) == 0 {
			return fmt.Errorf("%w: cut short", ErrOPACK)
		}
		if d.b[0] == 0x03 {
			d.b = d.b[1:]
			return nil
		}
		if err := item(); err != nil {
			return err
		}
	}
}
