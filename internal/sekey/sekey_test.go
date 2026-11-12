// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// TestEnclave runs on a Mac with CBB_SE_TEST=1: it makes a key, signs with
// it, loads it again from its blob and signs with that.
func TestEnclave(t *testing.T) {
	if os.Getenv(testEnv) != "1" {
		if _, err := New(); !errors.Is(err, ErrNoEnclave) {
			t.Fatalf("New in a test without %s=1: %v, want ErrNoEnclave", testEnv, err)
		}
		t.Skipf("set %s=1 on a Mac with a Secure Enclave", testEnv)
	}
	checkKeys(t)
}

// checkKeys makes a key, signs with it, loads it again from its blob and
// signs with that; a damaged blob does not load.
func checkKeys(t *testing.T) {
	k, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("blob: %d bytes", len(k.Blob()))
	sign := func(k *Key) {
		t.Helper()
		d256 := sha256.Sum256([]byte("cbb"))
		d384 := sha512.Sum384([]byte("cbb"))
		d512 := sha512.Sum512([]byte("cbb"))
		for _, c := range []struct {
			d []byte
			h crypto.Hash
		}{{d256[:], crypto.SHA256}, {d384[:], crypto.SHA384}, {d512[:], crypto.SHA512}} {
			sig, err := k.Sign(nil, c.d, c.h)
			if err != nil {
				t.Fatalf("%v: %v", c.h, err)
			}
			if !ecdsa.VerifyASN1(k.Public().(*ecdsa.PublicKey), c.d, sig) {
				t.Fatalf("%v: the signature does not verify", c.h)
			}
		}
		if _, err := k.Sign(nil, d256[:], crypto.SHA384); err == nil {
			t.Fatal("signed a digest of the wrong length")
		}
	}
	sign(k)
	l, err := Load(k.Blob())
	if err != nil {
		t.Fatal(err)
	}
	if !l.Public().(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Fatal("the loaded key has another public key")
	}
	sign(l)
	bad := k.Blob()
	bad[len(bad)/2] ^= 1
	if _, err := Load(bad); err == nil {
		t.Fatal("loaded a damaged blob")
	}
}

// TestSeal seals a secret in the enclave and opens it again.
func TestSeal(t *testing.T) {
	if os.Getenv(testEnv) != "1" {
		if _, err := Seal([]byte("x")); !errors.Is(err, ErrNoEnclave) {
			t.Fatalf("Seal in a test without %s=1: %v, want ErrNoEnclave", testEnv, err)
		}
		t.Skipf("set %s=1 on a Mac with a Secure Enclave", testEnv)
	}
	checkSeal(t)
}

// checkSeal seals a secret and opens it again; a damaged box does not open.
func checkSeal(t *testing.T) {
	secret := []byte("the WireGuard key, 32 bytes long")
	b, err := Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sealed: %s", b)
	got, err := Unseal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatalf("Unseal = %q, want %q", got, secret)
	}
	var s sealed
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	s.Box[len(s.Box)-1] ^= 1
	bad, _ := json.Marshal(s)
	if _, err := Unseal(bad); err == nil {
		t.Fatal("opened a damaged box")
	}
}
