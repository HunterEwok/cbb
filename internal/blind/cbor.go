// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package blind reads what the forwarder takes from a hub of 0.6
// (docs/protocol.md, sections 4, 13 and 18): the format's CBOR profile,
// its frames, envelopes signed with ES256, and the group's server
// credentials (`cbb credential v2`) with the checks a server makes on
// them. It is the forwarder's own reader of these, held to the Rust core's
// (core/src/format, core/src/blind/credential.rs) by the format's vectors
// (testdata/format) and fuzzed on the nightly run (D-106: one Rust
// implementation of these rules comes with 0.7). testdata/format/check,
// the vectors' independent second reader, shares no code with it.
package blind

import (
	"bytes"
	"sort"
	"unicode/utf8"
)

// Rule names the rule of the format a reading broke, as the Rust core
// names it (core/src/format/mod.rs), so the vectors' rules compare.
type Rule string

func (r Rule) Error() string { return string(r) }

// The profile's rules.
const (
	RuleNegative   Rule = "cbor/negative"
	RuleTag        Rule = "cbor/tag"
	RuleSimple     Rule = "cbor/simple"
	RuleIndefinite Rule = "cbor/indefinite"
	RuleReserved   Rule = "cbor/reserved"
	RuleShortest   Rule = "cbor/shortest"
	RuleIntRange   Rule = "cbor/int-range"
	RuleMapKey     Rule = "cbor/map-key"
	RuleMapOrder   Rule = "cbor/map-order"
	RuleUTF8       Rule = "cbor/utf8"
	RuleDepth      Rule = "cbor/depth"
	RuleCount      Rule = "cbor/count"
	RuleTrailing   Rule = "cbor/trailing"
	RuleTruncated  Rule = "cbor/truncated"
)

// The profile's bounds: nesting, elements of an array or pairs of a map,
// and the largest integer.
const (
	MaxDepth = 8
	MaxCount = 65535
	MaxInt   = 1<<63 - 1
)

// Kind is the type of a Value.
type Kind uint8

// The kinds of the profile: unsigned integers, byte strings, text, arrays
// and maps with small unsigned keys in increasing order.
const (
	KindUint Kind = iota
	KindBytes
	KindText
	KindArray
	KindMap
)

// Pair is a map's entry.
type Pair struct {
	Key   uint16
	Value Value
}

// Value is one item of the profile.
type Value struct {
	Kind  Kind
	Uint  uint64
	Bytes []byte // KindBytes, and KindText's UTF-8
	Array []Value
	Map   []Pair // keys in increasing order
}

// Uint, Bytes, Text, Array and Map make Values.
func Uint(n uint64) Value      { return Value{Kind: KindUint, Uint: n} }
func Bytes(b []byte) Value     { return Value{Kind: KindBytes, Bytes: b} }
func Text(s string) Value      { return Value{Kind: KindText, Bytes: []byte(s)} }
func Array(a ...Value) Value   { return Value{Kind: KindArray, Array: a} }
func Map(pairs ...Pair) Value  { return Value{Kind: KindMap, Map: pairs} }
func P(k uint16, v Value) Pair { return Pair{Key: k, Value: v} }
func (v Value) IsBytes() bool  { return v.Kind == KindBytes }
func (v Value) IsText() bool   { return v.Kind == KindText }
func (v Value) IsUint() bool   { return v.Kind == KindUint }
func (v Value) TextOf() string { return string(v.Bytes) }

// Get is a map's field k.
func (v Value) Get(k uint16) (Value, bool) {
	if v.Kind != KindMap {
		return Value{}, false
	}
	i := sort.Search(len(v.Map), func(i int) bool { return v.Map[i].Key >= k })
	if i < len(v.Map) && v.Map[i].Key == k {
		return v.Map[i].Value, true
	}
	return Value{}, false
}

// Decode reads b as exactly one item of the profile.
func Decode(b []byte) (Value, error) {
	r := reader{b: b}
	v, err := r.item(0)
	if err != nil {
		return Value{}, err
	}
	if r.pos != len(b) {
		return Value{}, RuleTrailing
	}
	return v, nil
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) take(n uint64) ([]byte, error) {
	if n > uint64(len(r.b)-r.pos) {
		return nil, RuleTruncated
	}
	s := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return s, nil
}

// arg reads a head's argument, refusing a longer form than it needs.
func (r *reader) arg(ai byte) (uint64, error) {
	var size int
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		size = 1
	case ai == 25:
		size = 2
	case ai == 26:
		size = 4
	case ai == 27:
		size = 8
	case ai == 31:
		return 0, RuleIndefinite
	default:
		return 0, RuleReserved
	}
	s, err := r.take(uint64(size))
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, c := range s {
		v = v<<8 | uint64(c)
	}
	min := map[int]uint64{1: 24, 2: 0x100, 4: 0x1_0000, 8: 0x1_0000_0000}[size]
	if v < min {
		return 0, RuleShortest
	}
	return v, nil
}

func (r *reader) item(depth int) (Value, error) {
	if r.pos >= len(r.b) {
		return Value{}, RuleTruncated
	}
	ib := r.b[r.pos]
	r.pos++
	major, ai := ib>>5, ib&31
	switch major {
	case 1:
		return Value{}, RuleNegative
	case 6:
		return Value{}, RuleTag
	case 7:
		return Value{}, RuleSimple
	}
	n, err := r.arg(ai)
	if err != nil {
		return Value{}, err
	}
	switch major {
	case 0:
		if n > MaxInt {
			return Value{}, RuleIntRange
		}
		return Uint(n), nil
	case 2:
		s, err := r.take(n)
		if err != nil {
			return Value{}, err
		}
		return Bytes(s), nil
	case 3:
		s, err := r.take(n)
		if err != nil {
			return Value{}, err
		}
		if !utf8.Valid(s) {
			return Value{}, RuleUTF8
		}
		return Value{Kind: KindText, Bytes: s}, nil
	}
	if depth >= MaxDepth {
		return Value{}, RuleDepth
	}
	if n > MaxCount {
		return Value{}, RuleCount
	}
	room := uint64(len(r.b) - r.pos)
	if major == 4 {
		a := make([]Value, 0, min(n, room))
		for range n {
			e, err := r.item(depth + 1)
			if err != nil {
				return Value{}, err
			}
			a = append(a, e)
		}
		return Array(a...), nil
	}
	m := make([]Pair, 0, min(n, room/2))
	for range n {
		if r.pos >= len(r.b) {
			return Value{}, RuleTruncated
		}
		if r.b[r.pos]>>5 != 0 {
			return Value{}, RuleMapKey
		}
		k, err := r.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		if k.Uint > 0xffff {
			return Value{}, RuleMapKey
		}
		if len(m) > 0 && uint16(k.Uint) <= m[len(m)-1].Key {
			return Value{}, RuleMapOrder
		}
		v, err := r.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		m = append(m, P(uint16(k.Uint), v))
	}
	return Map(m...), nil
}

// Encode writes v in the profile's one form: shortest heads, a map's keys
// in increasing order.
func Encode(v Value) []byte {
	var b bytes.Buffer
	encode(&b, v)
	return b.Bytes()
}

func head(b *bytes.Buffer, major byte, n uint64) {
	switch {
	case n < 24:
		b.WriteByte(major<<5 | byte(n))
	case n <= 0xff:
		b.Write([]byte{major<<5 | 24, byte(n)})
	case n <= 0xffff:
		b.Write([]byte{major<<5 | 25, byte(n >> 8), byte(n)})
	case n <= 0xffff_ffff:
		b.Write([]byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		b.WriteByte(major<<5 | 27)
		for i := 7; i >= 0; i-- {
			b.WriteByte(byte(n >> (8 * i)))
		}
	}
}

// headLen is the bytes a head with argument n takes.
func headLen(n uint64) int {
	switch {
	case n < 24:
		return 1
	case n <= 0xff:
		return 2
	case n <= 0xffff:
		return 3
	case n <= 0xffff_ffff:
		return 5
	default:
		return 9
	}
}

func encode(b *bytes.Buffer, v Value) {
	switch v.Kind {
	case KindUint:
		head(b, 0, v.Uint)
	case KindBytes:
		head(b, 2, uint64(len(v.Bytes)))
		b.Write(v.Bytes)
	case KindText:
		head(b, 3, uint64(len(v.Bytes)))
		b.Write(v.Bytes)
	case KindArray:
		head(b, 4, uint64(len(v.Array)))
		for _, e := range v.Array {
			encode(b, e)
		}
	case KindMap:
		m := append([]Pair(nil), v.Map...)
		sort.Slice(m, func(i, j int) bool { return m[i].Key < m[j].Key })
		head(b, 5, uint64(len(m)))
		for _, p := range m {
			head(b, 0, uint64(p.Key))
			encode(b, p.Value)
		}
	}
}
