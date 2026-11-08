// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
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
