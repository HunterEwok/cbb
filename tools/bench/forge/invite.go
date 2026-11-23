// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"

	"github.com/HunterEwok/cbb/internal/tunnel"
)

// An invitation to a hub that is not there (G15): forge
// invite:ADDR:PORT[,ADDR:PORT...] prints an invitation (docs/format.md,
// section 11.3) for a computer whose one guest path leads to a hub at
// those endpoints, so that a join with it reaches for the addresses and
// fails.

func inviteCase(arg string) bool { return strings.HasPrefix(arg, "invite:") }

func runInvite(arg string) error {
	var eps []string
	for _, s := range strings.Split(strings.TrimPrefix(arg, "invite:"), ",") {
		ep, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("invite:ADDR:PORT,..., not %q: %w", arg, err)
		}
		eps = append(eps, ep.String())
	}
	if len(eps) > 8 {
		return fmt.Errorf("invite: at most 8 endpoints, not %d", len(eps))
	}
	hub, err := tunnel.NewPrivateKey()
	if err != nil {
		return err
	}
	guest, err := tunnel.NewPrivateKey()
	if err != nil {
		return err
	}
	psk, err := tunnel.NewPresharedKey()
	if err != nil {
		return err
	}
	id, secret := make([]byte, 16), make([]byte, 32)
	rand.Read(id)
	rand.Read(secret)
	hubKey := hub.Public()
	var e cborWriter
	e.head(5, 4)
	e.uint(1)
	e.bytes(id)
	e.uint(2)
	e.bytes(secret)
	e.uint(3)
	e.head(4, 1)
	// The guest path: kind 2, the endpoints, the hub's key (alg 3,
	// X25519), the guest's key and pre-shared key.
	e.head(5, 5)
	e.uint(1)
	e.uint(2)
	e.uint(2)
	e.head(4, uint64(len(eps)))
	for _, s := range eps {
		e.text(s)
	}
	e.uint(3)
	e.head(4, 2)
	e.uint(3)
	e.bytes(hubKey[:])
	e.uint(4)
	e.bytes(guest[:])
	e.uint(5)
	e.bytes(psk[:])
	// The profile: a computer (role 1) that may read and send.
	e.uint(4)
	e.head(5, 2)
	e.uint(1)
	e.uint(1)
	e.uint(2)
	e.uint(3)
	fmt.Println("cbb://join#" + base64.RawURLEncoding.EncodeToString(e.b))
	return nil
}

// cborWriter writes CBOR in its shortest form: unsigned integers, byte and
// text strings, arrays and maps.
type cborWriter struct{ b []byte }

func (w *cborWriter) head(major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		w.b = append(w.b, m|byte(n))
	case n <= 0xff:
		w.b = append(w.b, m|24, byte(n))
	case n <= 0xffff:
		w.b = append(w.b, m|25, byte(n>>8), byte(n))
	default:
		w.b = append(w.b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func (w *cborWriter) uint(n uint64) { w.head(0, n) }

func (w *cborWriter) bytes(b []byte) {
	w.head(2, uint64(len(b)))
	w.b = append(w.b, b...)
}

func (w *cborWriter) text(s string) {
	w.head(3, uint64(len(s)))
	w.b = append(w.b, s...)
}
