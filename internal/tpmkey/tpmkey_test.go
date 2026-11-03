// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tpmkey_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/tpmkey"
	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

func TestKey(t *testing.T) {
	tpmtest.Start(t)
	tpm, err := tpmkey.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	k, err := tpm.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public().(*ecdsa.PublicKey)
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		var d []byte
		if h == crypto.SHA256 {
			s := sha256.Sum256([]byte("hello"))
			d = s[:]
		} else {
			s := sha512.Sum384([]byte("hello"))
			d = s[:]
		}
		sig, err := k.Sign(rand.Reader, d, h)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(pub, d, sig) {
			t.Errorf("%v: the signature does not verify", h)
		}
	}

	// The blob loads again after the TPM is opened anew, and signs a TLS
	// handshake.
	blob := k.Blob()
	tpm.Close()
	tpm, err = tpmkey.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	k, err = tpm.LoadKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Public().(*ecdsa.PublicKey).Equal(pub) {
		t.Fatal("the loaded key is another")
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tpm"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"tpm"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() {
		s := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
		done <- s.Handshake()
	}()
	c := tls.Client(b, &tls.Config{RootCAs: pool, ServerName: "tpm"})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A blob changed by a bit does not load.
	bad := tpmkey.Blob{Public: blob.Public, Private: append([]byte(nil), blob.Private...)}
	bad.Private[len(bad.Private)-1] ^= 1
	if _, err := tpm.LoadKey(bad); err == nil {
		t.Error("a changed blob loaded")
	}
}

func TestSeal(t *testing.T) {
	tpmtest.Start(t)
	tpm, err := tpmkey.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	secret := bytes.Repeat([]byte{0x5a}, 32)
	b, err := tpm.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Private, secret) || bytes.Contains(b.Public, secret) {
		t.Fatal("the blob holds the data in the clear")
	}
	// Another process, as after a restart, unseals it with the same TPM.
	tpm.Close()
	if tpm, err = tpmkey.Open(); err != nil {
		t.Fatal(err)
	}
	got, err := tpm.Unseal(b)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Unseal = %x, %v", got, err)
	}
	if _, err := tpm.Seal(make([]byte, tpmkey.MaxSealed+1)); err == nil {
		t.Error("sealed more than MaxSealed")
	}
	b.Private[len(b.Private)-1] ^= 1
	if _, err := tpm.Unseal(b); err == nil {
		t.Error("unsealed a tampered blob")
	}
	k, err := tpm.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpm.Unseal(k.Blob()); err == nil {
		t.Error("unsealed a signing key")
	}
}

// A TPM whose owner hierarchy has a password, as Windows sets one, takes
// keys and sealed objects under the storage root key at PersistentSRK,
// which needs none, and loads them again after a restart.
func TestOwnerPassword(t *testing.T) {
	tpmtest.Start(t)
	provision(t)
	tpm, err := tpmkey.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	k, err := tpm.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if k.Blob().Parent != tpmkey.PersistentSRK {
		t.Fatalf("the key's parent is %#x", k.Blob().Parent)
	}
	sealed, err := tpm.Seal([]byte("wireguard"))
	if err != nil {
		t.Fatal(err)
	}
	tpm.Close()
	if tpm, err = tpmkey.Open(); err != nil {
		t.Fatal(err)
	}
	again, err := tpm.LoadKey(k.Blob())
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("hello"))
	sig, err := again.Sign(rand.Reader, d[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(k.Public().(*ecdsa.PublicKey), d[:], sig) {
		t.Fatalf("signing with the loaded key: %v", err)
	}
	if got, err := tpm.Unseal(sealed); err != nil || string(got) != "wireguard" {
		t.Fatalf("Unseal = %q, %v", got, err)
	}
	if _, err := tpm.LoadKey(tpmkey.Blob{Public: k.Blob().Public, Private: k.Blob().Private}); err == nil {
		t.Error("a blob of the persistent key loaded under the one the template makes")
	}
}

// provision does what Windows does to the simulator: an RSA storage root
// key at PersistentSRK, then a password on the owner hierarchy that the
// service never learns.
func provision(t *testing.T) {
	t.Helper()
	addr := os.Getenv("CBB_TPM_SIMULATOR")
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	tr, err := tcp.Open(tcp.Config{CommandAddress: addr, PlatformAddress: net.JoinHostPort(host, strconv.Itoa(p+1))})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	srk, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.RSASRKTemplate)}.Execute(tr)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(tr)
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		PersistentHandle: tpm2.TPMIDHPersistent(tpmkey.PersistentSRK),
	}).Execute(tr); err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.TPMRHOwner,
		NewAuth:    tpm2.TPM2BAuth{Buffer: []byte("random, then forgotten")},
	}).Execute(tr); err != nil {
		t.Fatal(err)
	}
}
