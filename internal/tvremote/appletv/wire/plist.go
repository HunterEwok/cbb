// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"unicode/utf16"
)

// The text field's state and the text the remote types travel as binary
// property lists, in the form NSKeyedArchiver writes. This is the part of
// the format they use: booleans, integers, reals, data, strings, UIDs,
// arrays and dictionaries with string keys.

// UID is a reference to an object of an archive's "$objects".
type UID uint64

// ErrPlist is data that is not a binary property list this package reads.
var ErrPlist = errors.New("not a binary property list")

// EncodePlist writes v as a binary property list.
func EncodePlist(v any) ([]byte, error) {
	var w plistWriter
	if _, err := w.add(v, 0); err != nil {
		return nil, err
	}
	refSize := 1
	if len(w.objs) > math.MaxUint8 {
		refSize = 2
	}
	out := []byte("bplist00")
	offsets := make([]int, len(w.objs))
	for i, o := range w.objs {
		offsets[i] = len(out)
		out = append(out, o.head...)
		for _, r := range o.refs {
			out = appendBE(out, uint64(r), refSize)
		}
		out = append(out, o.tail...)
	}
	tableAt := len(out)
	offSize := 1
	for tableAt > 1<<(8*offSize)-1 {
		offSize *= 2
	}
	for _, o := range offsets {
		out = appendBE(out, uint64(o), offSize)
	}
	out = append(out, 0, 0, 0, 0, 0, 0, byte(offSize), byte(refSize))
	out = binary.BigEndian.AppendUint64(out, uint64(len(w.objs)))
	out = binary.BigEndian.AppendUint64(out, 0)
	out = binary.BigEndian.AppendUint64(out, uint64(tableAt))
	return out, nil
}

func appendBE(b []byte, v uint64, n int) []byte {
	for i := n - 1; i >= 0; i-- {
		b = append(b, byte(v>>(8*i)))
	}
	return b
}

type plistObj struct {
	head []byte
	refs []int
	tail []byte
}

type plistWriter struct {
	objs []plistObj
}

// marker writes a type's marker with its count: in the low nibble, or as
// an integer after 0xF.
func marker(typ byte, n int) []byte {
	if n < 15 {
		return []byte{typ<<4 | byte(n)}
	}
	return append([]byte{typ<<4 | 0xF}, plistInt(uint64(n))...)
}

func plistInt(v uint64) []byte {
	switch {
	case v <= math.MaxUint8:
		return []byte{0x10, byte(v)}
	case v <= math.MaxUint16:
		return binary.BigEndian.AppendUint16([]byte{0x11}, uint16(v))
	case v <= math.MaxUint32:
		return binary.BigEndian.AppendUint32([]byte{0x12}, uint32(v))
	}
	return binary.BigEndian.AppendUint64([]byte{0x13}, v)
}

func (w *plistWriter) add(v any, depth int) (int, error) {
	if depth > maxDepth {
		return 0, fmt.Errorf("a property list nested deeper than %d", maxDepth)
	}
	i := len(w.objs)
	w.objs = append(w.objs, plistObj{})
	var o plistObj
	switch x := v.(type) {
	case bool:
		o.head = []byte{0x08}
		if x {
			o.head = []byte{0x09}
		}
	case int:
		if x < 0 {
			return 0, errors.New("a property list's negative integer")
		}
		o.head = plistInt(uint64(x))
	case int64:
		if x < 0 {
			return 0, errors.New("a property list's negative integer")
		}
		o.head = plistInt(uint64(x))
	case float64:
		o.head = binary.BigEndian.AppendUint64([]byte{0x23}, math.Float64bits(x))
	case UID:
		b := appendBE(nil, uint64(x), uidSize(uint64(x)))
		o.head = append([]byte{0x80 | byte(len(b)-1)}, b...)
	case []byte:
		o.head = append(marker(0x4, len(x)), x...)
	case string:
		if isASCII(x) {
			o.head = append(marker(0x5, len(x)), x...)
		} else {
			u := utf16.Encode([]rune(x))
			o.head = marker(0x6, len(u))
			for _, c := range u {
				o.head = binary.BigEndian.AppendUint16(o.head, c)
			}
		}
	case []any:
		o.head = marker(0xA, len(x))
		for _, e := range x {
			r, err := w.add(e, depth+1)
			if err != nil {
				return 0, err
			}
			o.refs = append(o.refs, r)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		o.head = marker(0xD, len(x))
		var vals []int
		for _, k := range keys {
			r, err := w.add(k, depth+1)
			if err != nil {
				return 0, err
			}
			o.refs = append(o.refs, r)
		}
		for _, k := range keys {
			r, err := w.add(x[k], depth+1)
			if err != nil {
				return 0, err
			}
			vals = append(vals, r)
		}
		o.refs = append(o.refs, vals...)
	default:
		return 0, fmt.Errorf("a property list cannot hold %T", v)
	}
	w.objs[i] = o
	return i, nil
}

func uidSize(v uint64) int {
	switch {
	case v <= math.MaxUint8:
		return 1
	case v <= math.MaxUint16:
		return 2
	case v <= math.MaxUint32:
		return 4
	}
	return 8
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// DecodePlist reads a binary property list.
func DecodePlist(b []byte) (any, error) {
	if len(b) < 8+32 || string(b[:8]) != "bplist00" {
		return nil, ErrPlist
	}
	t := b[len(b)-32:]
	offSize, refSize := int(t[6]), int(t[7])
	n := binary.BigEndian.Uint64(t[8:])
	top := binary.BigEndian.Uint64(t[16:])
	tableAt := binary.BigEndian.Uint64(t[24:])
	body := uint64(len(b) - 32)
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || n == 0 || top >= n ||
		tableAt < 8 || tableAt > body || n > (body-tableAt)/uint64(offSize) {
		return nil, fmt.Errorf("%w: a bad trailer", ErrPlist)
	}
	r := plistReader{b: b[:tableAt], refSize: refSize, offsets: make([]uint64, n)}
	for i := range r.offsets {
		at := tableAt + uint64(i*offSize)
		r.offsets[i] = readBE(b[at : at+uint64(offSize)])
	}
	return r.object(top, 0)
}

func readBE(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

type plistReader struct {
	b       []byte
	refSize int
	offsets []uint64
	visits  int // objects read so far, shared ones each time
}

// maxVisits bounds the objects a list may make the reader read, counting
// an object each time a reference reaches it.
const maxVisits = 1 << 14

func (r *plistReader) bytes(at, n uint64) ([]byte, error) {
	if at > uint64(len(r.b)) || n > uint64(len(r.b))-at {
		return nil, fmt.Errorf("%w: cut short", ErrPlist)
	}
	return r.b[at : at+n], nil
}

// count reads the count in a marker's low nibble, or after it.
func (r *plistReader) count(at uint64, low byte) (n, next uint64, err error) {
	if low != 0xF {
		return uint64(low), at + 1, nil
	}
	h, err := r.bytes(at+1, 1)
	if err != nil {
		return 0, 0, err
	}
	if h[0]>>4 != 0x1 || h[0]&0xF > 3 {
		return 0, 0, fmt.Errorf("%w: a bad count", ErrPlist)
	}
	w := uint64(1) << (h[0] & 0xF)
	v, err := r.bytes(at+2, w)
	if err != nil {
		return 0, 0, err
	}
	return readBE(v), at + 2 + w, nil
}

func (r *plistReader) object(i uint64, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested deeper than %d", ErrPlist, maxDepth)
	}
	if r.visits++; r.visits > maxVisits {
		return nil, fmt.Errorf("%w: more than %d objects", ErrPlist, maxVisits)
	}
	if i >= uint64(len(r.offsets)) {
		return nil, fmt.Errorf("%w: a reference to object %d of %d", ErrPlist, i, len(r.offsets))
	}
	at := r.offsets[i]
	h, err := r.bytes(at, 1)
	if err != nil {
		return nil, err
	}
	typ, low := h[0]>>4, h[0]&0xF
	switch typ {
	case 0x0:
		switch low {
		case 0x8:
			return false, nil
		case 0x9:
			return true, nil
		}
	case 0x1:
		if low > 3 {
			break
		}
		v, err := r.bytes(at+1, 1<<low)
		if err != nil {
			return nil, err
		}
		return int64(readBE(v)), nil
	case 0x2:
		switch low {
		case 2:
			v, err := r.bytes(at+1, 4)
			if err != nil {
				return nil, err
			}
			return float64(math.Float32frombits(uint32(readBE(v)))), nil
		case 3:
			v, err := r.bytes(at+1, 8)
			if err != nil {
				return nil, err
			}
			return math.Float64frombits(readBE(v)), nil
		}
	case 0x4, 0x5, 0x6:
		n, next, err := r.count(at, low)
		if err != nil {
			return nil, err
		}
		size := n
		if typ == 0x6 {
			size = 2 * n
		}
		v, err := r.bytes(next, size)
		if err != nil {
			return nil, err
		}
		switch typ {
		case 0x4:
			return slices.Clone(v), nil
		case 0x5:
			return string(v), nil
		}
		u := make([]uint16, n)
		for j := range u {
			u[j] = binary.BigEndian.Uint16(v[2*j:])
		}
		return string(utf16.Decode(u)), nil
	case 0x8:
		v, err := r.bytes(at+1, uint64(low)+1)
		if err != nil {
			return nil, err
		}
		return UID(readBE(v)), nil
	case 0xA, 0xD:
		n, next, err := r.count(at, low)
		if err != nil {
			return nil, err
		}
		refs := n
		if typ == 0xD {
			refs = 2 * n
		}
		if refs > uint64(len(r.offsets))*2 {
			return nil, fmt.Errorf("%w: too many entries", ErrPlist)
		}
		raw, err := r.bytes(next, refs*uint64(r.refSize))
		if err != nil {
			return nil, err
		}
		ref := func(j uint64) uint64 {
			return readBE(raw[j*uint64(r.refSize) : (j+1)*uint64(r.refSize)])
		}
		if typ == 0xA {
			out := make([]any, n)
			for j := range n {
				if out[j], err = r.object(ref(j), depth+1); err != nil {
					return nil, err
				}
			}
			return out, nil
		}
		out := make(map[string]any, n)
		for j := range n {
			k, err := r.object(ref(j), depth+1)
			if err != nil {
				return nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%w: a key is %T, not a string", ErrPlist, k)
			}
			if out[key], err = r.object(ref(n+j), depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: marker %#x", ErrPlist, h[0])
}
