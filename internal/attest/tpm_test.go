// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package attest_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/tpmkey"
	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
)

// TestTPM runs a TPM's attestation of a key against swtpm with an EK
// certificate: the check passes, the TPM opens the credential, and every
// part that is changed or swapped fails the check.
func TestTPM(t *testing.T) {
	tpmtest.Start(t)
	roots := tpmtest.ProvisionEK(t)
	tpm, err := tpmkey.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	ek, err := tpm.Endorsement()
	if err != nil {
		t.Fatal(err)
	}
	ak, err := tpm.NewAK()
	if err != nil {
		t.Fatal(err)
	}
	key, err := tpm.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{7}, 32)
	at, sig, err := ak.Certify(key, challenge)
	if err != nil {
		t.Fatal(err)
	}
	ev := attest.TPMEvidence{EKCert: ek.Cert, EK: ek.Public, AK: ak.Public, Key: key.PublicArea(), Attest: at, Signature: sig}
	policy := attest.TPMPolicy{Roots: roots}

	res, cred, err := attest.CheckTPM(ev, spki, challenge, policy)
	if err != nil {
		t.Fatal(err)
	}
	if res.Store != attest.StoreProven || res.Kind != attest.KindTPM {
		t.Fatalf("result %+v", res)
	}
	got, err := ak.Activate(ek, cred.Credential, cred.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cred.Value) {
		t.Fatal("the TPM opened another value")
	}

	// An AK of the same TPM that did not certify the key cannot stand in,
	// and a credential for one AK does not open with another.
	other, err := tpm.NewAK()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Activate(ek, cred.Credential, cred.Secret); err == nil {
		t.Error("another AK opened the credential")
	}
	otherKey, err := tpm.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	otherSPKI, _ := x509.MarshalPKIXPublicKey(otherKey.Public())
	file := tpmtest.FileKeyArea(t)

	flip := func(b []byte) []byte {
		c := bytes.Clone(b)
		c[len(c)-1] ^= 1
		return c
	}
	for name, c := range map[string]struct {
		ev        attest.TPMEvidence
		spki      []byte
		challenge []byte
		policy    attest.TPMPolicy
	}{
		"no roots":          {ev, spki, challenge, attest.TPMPolicy{Roots: []*x509.Certificate{}}},
		"another root":      {ev, spki, challenge, attest.TPMPolicy{Roots: tpmtest.OtherRoots(t)}},
		"another member":    {ev, otherSPKI, challenge, policy},
		"another challenge": {ev, spki, bytes.Repeat([]byte{8}, 32), policy},
		"another AK":        {with(ev, func(e *attest.TPMEvidence) { e.AK = other.Public }), spki, challenge, policy},
		"another key":       {with(ev, func(e *attest.TPMEvidence) { e.Key = otherKey.PublicArea() }), otherSPKI, challenge, policy},
		"a key that leaves": {with(ev, func(e *attest.TPMEvidence) { e.Key = file }), spki, challenge, policy},
		"another EK":        {with(ev, func(e *attest.TPMEvidence) { e.EK = ak.Public }), spki, challenge, policy},
		"broken signature":  {with(ev, func(e *attest.TPMEvidence) { e.Signature = flip(sig) }), spki, challenge, policy},
		"broken attest":     {with(ev, func(e *attest.TPMEvidence) { e.Attest = flip(at) }), spki, challenge, policy},
		"broken EK cert":    {with(ev, func(e *attest.TPMEvidence) { e.EKCert = flip(ek.Cert) }), spki, challenge, policy},
	} {
		if _, _, err := attest.CheckTPM(c.ev, c.spki, c.challenge, c.policy); !errors.Is(err, attest.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func with(e attest.TPMEvidence, f func(*attest.TPMEvidence)) attest.TPMEvidence {
	f(&e)
	return e
}
