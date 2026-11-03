// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// zxUnpack is .cbb's unpacking (apps/zxnext/src/cbb.c, screen_open).
func zxUnpack(p []byte) []byte {
	var out []byte
	for i := 0; i < len(p); {
		n := p[i]
		i++
		if n < 128 {
			out = append(out, p[i:i+int(n)+1]...)
			i += int(n) + 1
			continue
		}
		out = append(out, bytes.Repeat([]byte{p[i]}, 257-int(n))...)
		i++
	}
	return out
}

func TestZXPack(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		data := make([]byte, r.IntN(600))
		for i := range data {
			// Few values, so that runs of every length come up.
			data[i] = byte(r.IntN(3))
			if r.IntN(4) == 0 {
				data[i] = byte(r.IntN(256))
			}
		}
		if got := zxUnpack(zxPack(data)); !bytes.Equal(got, data) {
			t.Fatalf("unpacked %x, want %x", got, data)
		}
	}
}
