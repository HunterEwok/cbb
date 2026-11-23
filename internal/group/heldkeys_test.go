// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"runtime"
	"testing"

	"github.com/HunterEwok/cbb/internal/keyseal"
	"github.com/HunterEwok/cbb/internal/tpmkey"
)

// A key or a secret kept by hardware that is not there, or kept without
// its blob, says so instead of loading something else.
func TestHeldKeysWithoutTheirHardware(t *testing.T) {
	if _, err := (HeldKey{}).Load(); err == nil {
		t.Error("a held key without its blob loaded")
	}
	if _, err := (Sealer{}).Unseal(&keyseal.Blob{}); err == nil {
		t.Error("a sealed secret without its blob opened")
	}
	if runtime.GOOS != "darwin" {
		if _, err := (storedKey{se: []byte{1, 2, 3}}).load(); err == nil {
			t.Error("a Secure Enclave key loaded where there is no enclave")
		}
		if _, err := (Sealer{}).Unseal(&keyseal.Blob{SE: []byte{1, 2, 3}}); err == nil {
			t.Error("a secret the Secure Enclave sealed opened where there is no enclave")
		}
	}
	if _, err := theTPM(); err != nil {
		if _, err := loadTPMKey(&tpmkey.Blob{}); err == nil {
			t.Error("a TPM key loaded where there is no TPM")
		}
		if _, err := (Sealer{}).Unseal(&keyseal.Blob{TPM: &tpmkey.Blob{}}); err == nil {
			t.Error("a secret the TPM sealed opened where there is no TPM")
		}
	}
}

// With CBB_TPM off nothing goes to the hardware, and the reason says so.
func TestHardwareOff(t *testing.T) {
	t.Setenv(TPMEnv, "off")
	if got := WhyNotHardware(); got != TPMEnv+" is off" {
		t.Errorf("WhyNotHardware() = %q", got)
	}
	if b, err := (Sealer{}).Seal([]byte("secret")); b != nil || err != nil {
		t.Errorf("Seal with CBB_TPM off: %v, %v", b, err)
	}
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, held := HeldOf(key); held {
		t.Error("a key in a file is held by hardware")
	}
}

// A key kept in the file loads back as the same P-256 key; a file key that
// is not PKCS #8, or not P-256, does not load.
func TestFileKeys(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := storeKey(key)
	if err != nil || s.der == nil {
		t.Fatalf("storeKey of a file key: %+v, %v", s, err)
	}
	got, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.(*ecdsa.PrivateKey).Equal(key) || KeyStoreOf(got) != StoreFile {
		t.Error("the file key loaded as another key")
	}

	if _, err := (storedKey{der: []byte{1, 2, 3}}).load(); err == nil {
		t.Error("a key that is not PKCS #8 loaded")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for name, k := range map[string]any{"P-384": p384, "Ed25519": ed} {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (storedKey{der: der}).load(); err == nil {
			t.Errorf("a %s key loaded as a device key", name)
		}
	}
}

// Without a TPM nothing failed, so there is no reason to give; CloseTPM
// leaves the TPM to open again when next used.
func TestNoTPM(t *testing.T) {
	CloseTPM()
	t.Cleanup(ReopenTPM)
	if _, err := theTPM(); !errors.Is(err, tpmkey.ErrNoTPM) {
		t.Skipf("this machine has a TPM: %v", err)
	}
	if got := WhyNotHardware(); got != "" {
		t.Errorf("WhyNotHardware() without a TPM = %q", got)
	}
	CloseTPM()
	if _, err := theTPM(); !errors.Is(err, tpmkey.ErrNoTPM) {
		t.Errorf("the TPM after CloseTPM: %v", err)
	}
}
