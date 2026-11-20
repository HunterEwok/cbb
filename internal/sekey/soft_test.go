// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sekey

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

// softRef is a software key in place of the enclave's: its blob is the
// public key, then the scalar, so a damaged blob loads and does not sign,
// as the enclave's does.
type softRef struct {
	k        *ecdsa.PrivateKey
	released *int
	fail     error
}

func (r softRef) release() { *r.released++ }

func (r softRef) sign(d []byte) ([]byte, error) {
	if r.fail != nil {
		return nil, r.fail
	}
	return ecdsa.SignASN1(rand.Reader, r.k, d)
}

func (r softRef) agree(pub []byte) ([]byte, error) {
	if r.fail != nil {
		return nil, r.fail
	}
	k, err := r.k.ECDH()
	if err != nil {
		return nil, err
	}
	p, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return k.ECDH(p)
}

// soft is a software enclave for a test: it counts the keys it released
// and makes its keys' sign and agree fail with fail.
type soft struct {
	released int
	fail     error
	pub      []byte // a public key to give in place of the key's
}

func useSoft(t *testing.T) *soft {
	t.Helper()
	t.Setenv(testEnv, "1")
	s := &soft{}
	a, c, l := enclaveAvailable, enclaveCreate, enclaveLoad
	t.Cleanup(func() { enclaveAvailable, enclaveCreate, enclaveLoad = a, c, l })
	enclaveAvailable = func() bool { return true }
	enclaveCreate = func() (keyRef, []byte, []byte, error) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		pub, _ := k.PublicKey.Bytes()
		scalar, _ := k.Bytes()
		if s.pub != nil {
			pub = s.pub
		}
		return softRef{k, &s.released, s.fail}, append(append([]byte(nil), pub...), scalar...), pub, nil
	}
	enclaveLoad = func(blob []byte) (keyRef, []byte, error) {
		if len(blob) != 65+32 {
			return nil, nil, errors.New("sekey: not a key")
		}
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), blob[65:])
		if err != nil {
			return nil, nil, err
		}
		return softRef{k, &s.released, s.fail}, blob[:65], nil
	}
	return s
}

// TestSoftEnclave runs the code around the enclave with a software one.
func TestSoftEnclave(t *testing.T) {
	s := useSoft(t)
	if !Available() {
		t.Fatal("not available")
	}
	checkKeys(t)
	checkSeal(t)
	if s.released == 0 {
		t.Error("released no key")
	}

	k, err := New()
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("cbb"))
	if _, err := k.Sign(nil, d[:], crypto.MD5); err == nil {
		t.Error("signed an MD5 digest")
	}
	if _, err := Load(nil); err == nil {
		t.Error("loaded no key")
	}

	// A key whose signatures are not the key's.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k.ref = softRef{other, &s.released, nil}
	if _, err := k.Sign(nil, d[:], crypto.SHA256); err == nil {
		t.Error("gave a signature that does not verify")
	}

	// An enclave that fails, and one that gives a key off the curve.
	b, err := Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	s.fail = errors.New("the enclave failed")
	if _, err := Unseal(b); err == nil {
		t.Error("unsealed with a failing enclave")
	}
	if k, err := New(); err != nil {
		t.Fatal(err)
	} else if _, err := k.Sign(nil, d[:], crypto.SHA256); err == nil {
		t.Error("signed with a failing enclave")
	}
	if _, err := Load(k.Blob()); err == nil {
		t.Error("loaded a key that does not sign")
	}
	s.fail = nil
	s.pub = make([]byte, 65)
	s.pub[0] = 4
	if _, err := New(); err == nil {
		t.Error("took a public key off the curve")
	}
	if _, err := Seal([]byte("x")); err == nil {
		t.Error("sealed to a key off the curve")
	}
}

func TestUnsealRefuses(t *testing.T) {
	useSoft(t)
	b, err := Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	var good sealed
	json.Unmarshal(b, &good)
	for name, change := range map[string]func(*sealed){
		"a version 2":       func(s *sealed) { s.V = 2 },
		"no ephemeral key":  func(s *sealed) { s.Eph = nil },
		"a damaged key":     func(s *sealed) { s.Key = s.Key[1:] },
		"a box too short":   func(s *sealed) { s.Box = s.Box[:5] },
		"another ephemeral": func(s *sealed) { e, _ := ecdh.P256().GenerateKey(rand.Reader); s.Eph = e.PublicKey().Bytes() },
	} {
		s := good
		s.Key = append([]byte(nil), good.Key...)
		change(&s)
		bad, _ := json.Marshal(s)
		if _, err := Unseal(bad); err == nil {
			t.Errorf("%s: unsealed", name)
		}
	}
	if _, err := Unseal([]byte("{")); err == nil {
		t.Error("unsealed broken JSON")
	}
	if _, err := sealAEAD(make([]byte, 31), nil, nil); err == nil {
		t.Error("took a short agreed secret")
	}
}
