// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// The NIST known answers of SLH-DSA-SHA2-128s (testdata/slhdsa), read with
// circl, which shares nothing with the Rust core's RustCrypto slh-dsa: key
// generation from the three seeds, deterministic signing, verification,
// and the same changed inputs core/tests/slhdsa.rs gives the core.
type slhCase struct {
	Tc                                  int
	Sk, Pk, Message, Context, Signature string
	Valid                               *bool
	Reason                              string
}

func slhVerify(pk, msg, sig, ctx []byte) bool {
	var k slhdsa.PublicKey
	k.ID = slhdsa.SHA2_128s
	if k.UnmarshalBinary(pk) != nil {
		return false
	}
	return slhdsa.Verify(&k, slhdsa.NewMessage(msg), sig, ctx)
}

type slhInput struct {
	name              string
	pk, msg, sig, ctx []byte
}

// slhChanged builds the changed inputs by the rule of core/tests/slhdsa.rs.
func slhChanged(pk, msg, sig, ctx []byte) []slhInput {
	flip := func(b []byte, i int, bit uint) []byte {
		c := bytes.Clone(b)
		c[i] ^= 1 << bit
		return c
	}
	var out []slhInput
	out = append(out, slhInput{"key first bit", flip(pk, 0, 0), msg, sig, ctx})
	out = append(out, slhInput{"key last bit", flip(pk, len(pk)-1, 7), msg, sig, ctx})
	if len(msg) > 0 {
		out = append(out, slhInput{"message first bit", pk, flip(msg, 0, 0), sig, ctx})
		out = append(out, slhInput{"message last bit", pk, flip(msg, len(msg)-1, 7), sig, ctx})
	}
	out = append(out, slhInput{"signature R", pk, msg, flip(sig, 0, 0), ctx})
	out = append(out, slhInput{"signature FORS", pk, msg, flip(sig, 16, 3), ctx})
	out = append(out, slhInput{"signature last bit", pk, msg, flip(sig, len(sig)-1, 7), ctx})
	out = append(out, slhInput{"signature a byte short", pk, msg, sig[:len(sig)-1], ctx})
	out = append(out, slhInput{"signature a byte long", pk, msg, append(bytes.Clone(sig), 0), ctx})
	out = append(out, slhInput{"key a byte short", pk[:len(pk)-1], msg, sig, ctx})
	out = append(out, slhInput{"context a byte longer", pk, msg, sig, append(bytes.Clone(ctx), 0x5a)})
	return out
}

func checkSLHDSA(dir string) {
	b, err := os.ReadFile(filepath.Join(dir, "..", "slhdsa", "acvp-sha2-128s.json"))
	must(err)
	var raw struct {
		Keygen []map[string]any
		Siggen []slhCase
		Sigver []slhCase
	}
	must(json.Unmarshal(b, &raw))
	for _, t := range raw.Keygen {
		seed := func(k string) []byte { return unhex(t[k].(string)) }
		r := bytes.NewReader(append(append(seed("sk_seed"), seed("sk_prf")...), seed("pk_seed")...))
		pub, _, err := slhdsa.GenerateKey(r, slhdsa.SHA2_128s)
		must(err)
		pk, err := pub.MarshalBinary()
		must(err)
		if !bytes.Equal(pk, seed("pk")) {
			fail("slhdsa keygen tc %v: public key differs", t["tc"])
		}
	}
	for _, t := range raw.Siggen {
		var sk slhdsa.PrivateKey
		sk.ID = slhdsa.SHA2_128s
		must(sk.UnmarshalBinary(unhex(t.Sk)))
		sig, err := slhdsa.SignDeterministic(&sk, slhdsa.NewMessage(unhex(t.Message)), unhex(t.Context))
		must(err)
		if !bytes.Equal(sig, unhex(t.Signature)) {
			fail("slhdsa siggen tc %d: signature differs", t.Tc)
		}
	}
	valid := 0
	for _, t := range raw.Sigver {
		got := slhVerify(unhex(t.Pk), unhex(t.Message), unhex(t.Signature), unhex(t.Context))
		if t.Valid == nil || got != *t.Valid {
			fail("slhdsa sigver tc %d (%s): got %v", t.Tc, t.Reason, got)
		}
		if got {
			valid++
		}
	}
	changed := 0
	for _, t := range append(raw.Siggen, raw.Sigver...) {
		if t.Valid != nil && !*t.Valid {
			continue
		}
		pk, msg, sig, ctx := unhex(t.Pk), unhex(t.Message), unhex(t.Signature), unhex(t.Context)
		if !slhVerify(pk, msg, sig, ctx) {
			fail("slhdsa tc %d: the unchanged input is refused", t.Tc)
		}
		for _, c := range slhChanged(pk, msg, sig, ctx) {
			if slhVerify(c.pk, c.msg, c.sig, c.ctx) {
				fail("slhdsa tc %d: %s is taken", t.Tc, c.name)
			}
			changed++
		}
	}
	if valid == 0 || changed < 90 {
		fail("slhdsa: %d valid, %d changed inputs", valid, changed)
	}
	fmt.Printf("%-18s %d checked\n", "slhdsa (NIST)", len(raw.Keygen)+len(raw.Siggen)+len(raw.Sigver)+changed)
}
