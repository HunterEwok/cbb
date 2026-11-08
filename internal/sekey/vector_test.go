// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sekey

import (
	"crypto/ecdh"
	"encoding/json"
	"os"
	"testing"
)

// TestSealVector: testdata/interop/go-sekey-seal.json, which the Rust
// service's sekey.rs checks its sealing against, is what Seal makes: the
// enclave key there is the software key whose scalar is its blob.
func TestSealVector(t *testing.T) {
	b, err := os.ReadFile("../../testdata/interop/go-sekey-seal.json")
	if err != nil {
		t.Fatal(err)
	}
	var s sealed
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.P256().NewPrivateKey(s.Key)
	if err != nil {
		t.Fatal(err)
	}
	eph, err := ecdh.P256().NewPublicKey(s.Eph)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := k.ECDH(eph)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := sealAEAD(shared, s.Eph, k.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	n := aead.NonceSize()
	secret, err := aead.Open(nil, s.Box[:n], s.Box[n:], []byte(sealInfo))
	if err != nil || string(secret) != "the wireguard key" || s.V != 1 {
		t.Fatalf("the vector opens to %q, %v", secret, err)
	}
}
