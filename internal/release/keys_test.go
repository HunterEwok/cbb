// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"slices"
	"testing"
)

// TestSignerPEM checks that a signer written as PEM reads back as the same
// key, whole or a half at a time, as release-sign keeps the halves of a
// drill's key.
func TestSignerPEM(t *testing.T) {
	s := newSigner(t)
	text, err := MarshalSignerPEM(s.key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSigner(text)
	if err != nil {
		t.Fatal(err)
	}
	pubs, err := back.PublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	for alg, spki := range s.pubs {
		if !bytes.Equal(pubs[alg], spki) {
			t.Errorf("the half of algorithm %d changed", alg)
		}
	}

	// Each block alone is one half; together, in two texts, the signer.
	var halves [][]byte
	for rest := text; ; {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		rest = r
		halves = append(halves, pem.EncodeToMemory(b))
	}
	if len(halves) != 2 {
		t.Fatalf("%d PEM blocks, not 2", len(halves))
	}
	for _, h := range halves {
		k, err := ParseHalf(h)
		if err != nil {
			t.Fatal(err)
		}
		alg, spki, err := MarshalPublic(k.Public())
		if err != nil || !bytes.Equal(spki, s.pubs[alg]) {
			t.Errorf("a half read alone is not the signer's: %v", err)
		}
	}
	if _, err := ParseSigner(halves[0], halves[1]); err != nil {
		t.Errorf("the halves in two texts: %v", err)
	}
	if _, err := ParseSigner(halves[0]); err == nil {
		t.Error("one half read as a whole signer")
	}
	if _, err := ParseHalf(text); err == nil {
		t.Error("two keys read as one half")
	}
	if _, err := ParseHalf([]byte("no PEM here")); err == nil {
		t.Error("a text without PEM read as a half")
	}

	// A signed file verifies under the key read back.
	f, err := SignUnchecked([]byte(`{"type":"drill"}`), back)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.VerifyWith(s.keys("drill", "")); err != nil {
		t.Errorf("a file signed by the key read back: %v", err)
	}
	if err := f.VerifyWith(newSigner(t).keys("other", "")); err == nil {
		t.Error("a file verified under another key")
	}
}

// TestParsePrivateForms checks the private keys parsePrivate takes: a
// P-256 key as EC PRIVATE KEY and in PKCS#8, an SLH-DSA key in PKCS#8,
// and nothing else.
func TestParsePrivateForms(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseHalf(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	if err != nil || !k.Public().(*ecdsa.PublicKey).Equal(&ec.PublicKey) {
		t.Errorf("EC PRIVATE KEY: %v", err)
	}
	if _, err := ParseHalf(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: sec1})); err == nil {
		t.Error("a PUBLIC KEY read as a private half")
	}
	if _, err := ParseHalf(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})); err == nil {
		t.Error("a broken PRIVATE KEY read")
	}

	slh, err := GenerateSLH(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := MarshalSLHPEM(slh)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseHalf(p)
	if err != nil {
		t.Fatal(err)
	}
	_, want, _ := MarshalPublic(slh.Public())
	if alg, got, err := MarshalPublic(back.Public()); err != nil || alg != AlgSLHDSA || !bytes.Equal(got, want) {
		t.Errorf("the SLH-DSA half read back: %d %v", alg, err)
	}
	if _, err := MarshalSLHPEM(ec); err == nil {
		t.Error("a P-256 key written as an SLH-DSA key")
	}
	if _, err := ParseSLH(make([]byte, 10)); err == nil {
		t.Error("10 bytes read as an SLH-DSA key")
	}
}

// TestReadHalves checks the public halves release-sign reads: one of each
// algorithm, PUBLIC KEY blocks only, and ParsePublic's SLH-DSA key.
func TestReadHalves(t *testing.T) {
	s := newSigner(t)
	text, err := PublicPEM(s.key, "")
	if err != nil {
		t.Fatal(err)
	}
	halves, err := ReadHalves(text)
	if err != nil {
		t.Fatal(err)
	}
	for alg, spki := range s.pubs {
		if !bytes.Equal(halves[alg], spki) {
			t.Errorf("the half of algorithm %d", alg)
		}
	}
	pub, err := ParsePublic(AlgSLHDSA, halves[AlgSLHDSA])
	if err != nil {
		t.Fatal(err)
	}
	if _, spki, err := MarshalPublic(pub); err != nil || !bytes.Equal(spki, s.pubs[AlgSLHDSA]) {
		t.Errorf("ParsePublic gave another key: %v", err)
	}
	if _, err := ParsePublic(AlgES256, halves[AlgES256]); err == nil {
		t.Error("ParsePublic took a P-256 key")
	}
	if _, err := ParsePublic(AlgSLHDSA, halves[AlgES256]); err == nil {
		t.Error("ParsePublic took a P-256 key named SLH-DSA")
	}

	for name, data := range map[string][]byte{
		"nothing":       nil,
		"a private key": func() []byte { b, _ := MarshalSignerPEM(s.key); return b }(),
		"a half twice":  append(slices.Clone(text), text...),
		"not a key":     pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}}),
	} {
		if _, err := ReadHalves(data); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// TestEncodeRoots checks that roots written by EncodeRoots read back by
// ParseRoots as they were.
func TestEncodeRoots(t *testing.T) {
	want := roots(newSigner(t), newSigner(t))
	want[0].Name, want[1].Name = "root-a", "root-a"
	want[2].Name, want[3].Name = "root-b", "root-b"
	if _, err := ParseRoots(EncodeRoots(nil)); err == nil {
		t.Error("no roots read as roots")
	}
	got, err := ParseRoots(EncodeRoots(want))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("%d roots, not %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Alg != want[i].Alg || !bytes.Equal(got[i].Key, want[i].Key) {
			t.Errorf("root %d: %s %d", i, got[i].Name, got[i].Alg)
		}
	}
}

// TestCheckBody checks that CheckBody refuses what Sign refuses and takes
// what Sign signs.
func TestCheckBody(t *testing.T) {
	s := newSigner(t)
	good, err := json.Marshal(Keys{V: 1, Type: TypeKeys, Seq: 1, TimeMS: 1, ExpiresMS: 2, Keys: s.keys("k", "")})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckBody(good); err != nil {
		t.Errorf("a good keys.json: %v", err)
	}
	for name, body := range map[string][]byte{
		"not JSON":     []byte("{"),
		"no type":      []byte(`{"v":1}`),
		"unknown type": []byte(`{"v":1,"type":"nope"}`),
		"too large":    append([]byte(`{"type":"keys","x":"`), append(bytes.Repeat([]byte("a"), MaxBody), '"', '}')...),
	} {
		if err := CheckBody(body); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// TestSerialsAndVersions checks SortSerials' order, Status.Revoked and
// IsVersion.
func TestSerialsAndVersions(t *testing.T) {
	s := []string{"ff", "a", "100", "1f", "b"}
	SortSerials(s)
	if want := []string{"a", "b", "1f", "ff", "100"}; !slices.Equal(s, want) {
		t.Errorf("SortSerials = %v, want %v", s, want)
	}
	r := Status{AndroidRevoked: []string{"a", "1f"}}.Revoked()
	if len(r) != 2 || !r["a"] || !r["1f"] || r["b"] {
		t.Errorf("Revoked = %v", r)
	}
	for v, ok := range map[string]bool{
		"0.6.0": true, "0.6.0-rc.1": true, "10.20.30": true,
		"v0.6.0": false, "0.6": false, "0.6.0-beta.1": false, "": false, "0.6.0-rc.": false,
	} {
		if IsVersion(v) != ok {
			t.Errorf("IsVersion(%q) = %v", v, !ok)
		}
	}
}
