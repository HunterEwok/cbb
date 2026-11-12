// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"crypto/rand"
	"testing"
)

// The verifiers alone, to measure what checking a release file costs:
// go test -run X -bench Verify ./internal/release.
func BenchmarkSLHVerify(b *testing.B) {
	s, err := GenerateSigner()
	if err != nil {
		b.Fatal(err)
	}
	body := make([]byte, 2000)
	rand.Read(body)
	f, err := signData(body, s)
	if err != nil {
		b.Fatal(err)
	}
	var sig []byte
	for _, g := range f.Sigs {
		if g.Alg == AlgSLHDSA {
			sig = g.Sig
		}
	}
	_, spki, _ := MarshalPublic(s[1].Public())
	for b.Loop() {
		if !verifyHalf(AlgSLHDSA, spki, body, sig) {
			b.Fatal("no")
		}
	}
}

func BenchmarkES256Verify(b *testing.B) {
	s, _ := GenerateSigner()
	body := make([]byte, 2000)
	f, _ := signData(body, s)
	_, spki, _ := MarshalPublic(s[0].Public())
	for b.Loop() {
		if !verifyHalf(AlgES256, spki, body, f.Sigs[0].Sig) {
			b.Fatal("no")
		}
	}
}
