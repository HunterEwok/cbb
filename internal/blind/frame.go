// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package blind

import (
	"encoding/binary"
	"io"
	"slices"
)

// The frame's rules.
const (
	RuleFrameGrid    Rule = "frame/grid"
	RuleFramePad     Rule = "frame/pad"
	RuleFrameMessage Rule = "frame/message"
)

// A message's type and padding fields.
const (
	FieldT   = 0
	fieldPad = 1
)

// grid is the lengths a frame's body may have below gridStep; above it,
// every multiple of gridStep.
var grid = []int{64, 256, 1024, 4096, 16384}

const gridStep = 16384

// OnGrid reports whether n is a length a frame's body may have.
func OnGrid(n int) bool {
	return slices.Contains(grid, n) || (n > gridStep && n%gridStep == 0)
}

func gridAtLeast(n int) int {
	for _, g := range grid {
		if g >= n {
			return g
		}
	}
	return (n + gridStep - 1) / gridStep * gridStep
}

// padLength is the length of the padding a message of base bytes with
// entries fields takes to reach the grid, and the length it then has;
// ok is false when base is on the grid already.
func padLength(base, entries int) (plen, total int, ok bool) {
	if OnGrid(base) {
		return 0, 0, false
	}
	grow := headLen(uint64(entries+1)) - headLen(uint64(entries))
	fixed := base + grow + 1
	target := gridAtLeast(fixed + 1)
	for {
		for _, hl := range []int{1, 2, 3, 5, 9} {
			p := target - fixed - hl
			if p >= 0 && headLen(uint64(p)) == hl {
				return p, target, true
			}
		}
		target = gridAtLeast(target + 1)
	}
}

// padExact reports whether zeros is the padding a message of size bytes
// with entries fields (the padding among them) must have.
func padExact(size int, zeros []byte, entries int) bool {
	for _, z := range zeros {
		if z != 0 {
			return false
		}
	}
	rest := entries - 1
	shrink := headLen(uint64(entries)) - headLen(uint64(rest))
	base := size - (headLen(uint64(len(zeros))) + len(zeros) + shrink + 1)
	if base < 0 {
		return false
	}
	p, total, ok := padLength(base, rest)
	return ok && p == len(zeros) && total == size
}

// WriteFrame writes a message, its fields with its type in field 0, as a
// frame: its length on the grid, then the map, padded to that length.
func WriteFrame(fields ...Pair) []byte {
	entries := slices.DeleteFunc(slices.Clone(fields), func(p Pair) bool { return p.Key == fieldPad })
	body := Encode(Map(entries...))
	if p, _, ok := padLength(len(body), len(entries)); ok {
		body = Encode(Map(append(entries, P(fieldPad, Bytes(make([]byte, p))))...))
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	return append(out, body...)
}

// FrameLength checks a frame's length header against the grid and limit.
func FrameLength(header [4]byte, limit int) (int, error) {
	n := int(binary.BigEndian.Uint32(header[:]))
	if n == 0 || n > limit || !OnGrid(n) {
		return 0, RuleFrameGrid
	}
	return n, nil
}

// Message reads a frame's body: on the grid, a map of the profile with its
// type, its padding exact.
func Message(b []byte) (t uint64, m Value, err error) {
	if !OnGrid(len(b)) {
		return 0, Value{}, RuleFrameGrid
	}
	if m, err = Decode(b); err != nil {
		return 0, Value{}, err
	}
	if m.Kind != KindMap {
		return 0, Value{}, RuleFrameMessage
	}
	tv, ok := m.Get(FieldT)
	if !ok || !tv.IsUint() {
		return 0, Value{}, RuleFrameMessage
	}
	if pad, ok := m.Get(fieldPad); ok {
		if !pad.IsBytes() || !padExact(len(b), pad.Bytes, len(m.Map)) {
			return 0, Value{}, RuleFramePad
		}
	}
	return tv.Uint, m, nil
}

// ReadFrame reads one frame of at most limit bytes from r.
func ReadFrame(r io.Reader, limit int) (t uint64, m Value, body []byte, err error) {
	var h [4]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return 0, Value{}, nil, err
	}
	n, err := FrameLength(h, limit)
	if err != nil {
		return 0, Value{}, nil, err
	}
	body = make([]byte, n)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, Value{}, nil, err
	}
	t, m, err = Message(body)
	return t, m, body, err
}
