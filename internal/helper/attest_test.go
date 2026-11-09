// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAndroidRootsOfTests checks that the roots a test names are taken as
// public keys and as certificates, and that without the file the policy's
// own, Google's, apply.
func TestAndroidRootsOfTests(t *testing.T) {
	t.Setenv("CBB_TEST_ATTEST_ROOTS", "")
	if r, err := androidRoots(); r != nil || err != nil {
		t.Fatalf("without the file: %v, %v", r, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a root"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	f := filepath.Join(t.TempDir(), "roots.pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CBB_TEST_ATTEST_ROOTS", f)
	r, err := androidRoots()
	if err != nil || len(r) != 2 || !bytes.Equal(r[0], spki) || !bytes.Equal(r[1], cert.RawSubjectPublicKeyInfo) {
		t.Fatalf("the roots: %d, %v", len(r), err)
	}
}
