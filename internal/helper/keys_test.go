// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/piv"
	"github.com/HunterEwok/cbb/internal/piv/pivtest"
	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
)

func request(t *testing.T, op string, seq uint64, v any) control.Message {
	t.Helper()
	p, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return control.Message{Header: control.Header{Op: op, Seq: seq}, Payload: p}
}

func verifies(t *testing.T, public, digest, sig []byte) bool {
	t.Helper()
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), public)
	if err != nil {
		t.Fatalf("public key %x is not a P-256 point: %v", public, err)
	}
	return ecdsa.VerifyASN1(pub, digest, sig)
}

// TestKeysInTPM: key-new makes a device key in the TPM, which key-public
// loads again by its blob and key-sign signs with; the key never leaves
// the helper.
func TestKeysInTPM(t *testing.T) {
	tpmtest.Start(t)
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	s := New("test")
	s.HandleKeys()
	got := exchange(t, s, control.Message{Header: control.Header{Op: OpKeyNew, Seq: 1}})
	var k Key
	if err := json.Unmarshal(got[1].Payload, &k); err != nil || got[1].Error != "" {
		t.Fatalf("key-new: %v, %+v", err, got[1].Header)
	}
	if k.TPM == nil || len(k.Public) != 65 {
		t.Fatalf("key-new made no key in the TPM: %+v", k)
	}

	// A new helper, as after a restart, loads it from its blob.
	s = New("test")
	s.HandleKeys()
	digest := sha256.Sum256([]byte("a handshake"))
	got = exchange(t, s,
		request(t, OpKeyPublic, 2, k.HeldKey),
		request(t, OpKeySign, 3, Sign{HeldKey: k.HeldKey, Digest: digest[:]}),
		request(t, OpKeySign, 4, Sign{HeldKey: k.HeldKey, Digest: digest[:5]}),
		request(t, OpKeySign, 5, Sign{Digest: digest[:]}),
	)
	var again Key
	if err := json.Unmarshal(got[2].Payload, &again); err != nil || string(again.Public) != string(k.Public) {
		t.Fatalf("key-public: %v, %+v", err, got[2].Header)
	}
	if got[3].Error != "" || !verifies(t, k.Public, digest[:], got[3].Payload) {
		t.Fatalf("key-sign's signature does not verify: %+v", got[3].Header)
	}
	if got[4].Error == "" || got[5].Error == "" {
		t.Errorf("key-sign signed a short digest (%q) or without a key (%q)", got[4].Error, got[5].Error)
	}
}

// TestSealInTPM: seal seals a secret in the TPM, unseal in a new helper
// opens it, and a broken request is refused.
func TestSealInTPM(t *testing.T) {
	tpmtest.Start(t)
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	s := New("test")
	s.HandleKeys()
	got := exchange(t, s, request(t, OpSeal, 1, Sealed{Secret: []byte("a tunnel key")}))
	var b Sealed
	if err := json.Unmarshal(got[1].Payload, &b); err != nil || got[1].Error != "" || b.TPM == nil || b.Secret != nil {
		t.Fatalf("seal: %v, %+v, %+v", err, got[1].Header, b)
	}
	s = New("test")
	s.HandleKeys()
	got = exchange(t, s, request(t, OpUnseal, 2, b), request(t, OpUnseal, 3, Sealed{}))
	var open Sealed
	if err := json.Unmarshal(got[2].Payload, &open); err != nil || string(open.Secret) != "a tunnel key" {
		t.Fatalf("unseal: %v, %+v", err, got[2].Header)
	}
	if got[3].Error == "" {
		t.Error("unseal took a request without a blob")
	}
}

// TestKeysWithoutHardware: where new keys go into a file, key-new makes
// none and says why, so that cbb keeps the key in its own file.
func TestKeysWithoutHardware(t *testing.T) {
	t.Setenv(group.TPMEnv, "off")
	s := New("test")
	s.HandleKeys()
	got := exchange(t, s, control.Message{Header: control.Header{Op: OpKeyNew, Seq: 1}})
	var k Key
	if err := json.Unmarshal(got[1].Payload, &k); err != nil || got[1].Error != "" {
		t.Fatalf("key-new: %v, %+v", err, got[1].Header)
	}
	if k.TPM != nil || k.SE != nil || len(k.Public) != 0 || !strings.Contains(k.Why, group.TPMEnv) {
		t.Errorf("key-new without hardware: %+v", k)
	}
	got = exchange(t, s, request(t, OpSeal, 2, Sealed{Secret: []byte("a tunnel key")}))
	var b Sealed
	if err := json.Unmarshal(got[2].Payload, &b); err != nil || got[2].Error != "" || b.TPM != nil || b.SE != nil {
		t.Errorf("seal without hardware: %v, %+v, %+v", err, got[2].Header, b)
	}
}

// TestCardSign: card-sign finds the YubiKey slot by its key's hash, takes
// the PIN, and the card signs; a wrong PIN signs nothing.
func TestCardSign(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "recovery"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	card := pivtest.New(0x84, key, cert)
	open := func(match func(*x509.Certificate) bool) (*piv.Key, error) {
		card.Connect()
		if s, ok := card.Slot(0x84); ok && match(s.Cert) {
			if err := piv.Select(card); err != nil {
				return nil, err
			}
			return &piv.Key{Card: card, Slot: 0x84, Cert: s.Cert}, nil
		}
		return nil, piv.ErrNoKey
	}
	s := New("test")
	s.handleKeys(open)
	hash := group.KeyHashOf(cert)
	digest := sha256.Sum256([]byte("a claim"))
	got := exchange(t, s,
		request(t, OpCardSign, 1, CardSign{KeyHash: hash[:], PIN: "000000", Digest: digest[:]}),
	)
	if !strings.Contains(got[1].Error, "PIN") || card.Signed() != 0 {
		t.Fatalf("card-sign with a wrong PIN: %+v, %d signatures", got[1].Header, card.Signed())
	}
	got = exchange(t, s,
		request(t, OpCardSign, 2, CardSign{KeyHash: hash[:], PIN: "123456", Digest: digest[:]}),
		request(t, OpCardSign, 3, CardSign{KeyHash: make([]byte, 32), PIN: "123456", Digest: digest[:]}),
	)
	var signed Signed
	if err := json.Unmarshal(got[2].Payload, &signed); err != nil || got[2].Error != "" {
		t.Fatalf("card-sign: %v, %+v", err, got[2].Header)
	}
	if string(signed.Cert) != string(der) || !ecdsa.VerifyASN1(&key.PublicKey, digest[:], signed.Sig) {
		t.Error("card-sign's signature or certificate is not the card's key's")
	}
	if got[3].Error == "" {
		t.Error("card-sign signed with a key the card does not hold")
	}
}
