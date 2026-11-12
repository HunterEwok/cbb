// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/release"
)

// fakeAge stands in for age: "encrypting" writes the data under a header
// naming the recipient, "decrypting" checks the identity names it.
func fakeAge(t *testing.T) {
	prevE, prevD := ageEncrypt, ageDecrypt
	ageEncrypt = func(recipient, file string, data []byte) error {
		return os.WriteFile(file, append([]byte("to "+recipient+"\n"), data...), 0o600)
	}
	ageDecrypt = func(identity, file string) ([]byte, error) {
		id, err := os.ReadFile(identity)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		head, rest, _ := bytes.Cut(data, []byte("\n"))
		if string(head) != "to "+strings.TrimSpace(string(id)) {
			return nil, os.ErrPermission
		}
		return rest, nil
	}
	t.Cleanup(func() { ageEncrypt, ageDecrypt = prevE, prevD })
}

// ecFile writes a P-256 key alone, as a classical half.
func ecFile(t *testing.T, dir string) string {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(k)
	return write(t, filepath.Join(dir, "ec.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// TestPQNew: pq-new encrypts the half to the hardware's recipient under
// the classical half's name, and a signer of the classical half alone then
// finds it and signs twice.
func TestPQNew(t *testing.T) {
	fakeAge(t)
	dir := t.TempDir()
	t.Setenv("CBB_RELEASE_PQ_DIR", filepath.Join(dir, "pq"))
	ec := ecFile(t, dir)
	id := write(t, filepath.Join(dir, "yubikey.identity"), []byte("age1yubikey1test\n"))
	pubs := call(t, pqNew, "-key", "file:"+ec, "-to", "age1yubikey1test", "-identity", id, "-name", "root-9")
	roots, err := release.ParseRoots(pubs)
	if err != nil || len(roots) != 2 || roots[0].Name != "root-9" {
		t.Fatalf("pq-new printed %s (%v)", pubs, err)
	}
	if pqNew([]string{"-key", "file:" + ec, "-to", "age1yubikey1test", "-identity", id}) == nil {
		t.Error("pq-new replaced a half that exists")
	}
	// The file alone is no key: it is encrypted.
	entries, _ := os.ReadDir(filepath.Join(dir, "pq"))
	if len(entries) != 2 {
		t.Fatalf("pq holds %d files", len(entries))
	}
	// file:EC.pem alone holds one half; the PQ half comes from pq.
	if _, err := signer("file:" + ec); err == nil {
		t.Error("a file with one half signed")
	}
	c, err := classicalSigner("file:" + ec)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := pqOf(c, "")
	if err != nil {
		t.Fatal(err)
	}
	s := release.Signer{c, pq}
	at := now().UnixMilli()
	kb := release.Keys{V: 1, Type: release.TypeKeys, Seq: 1, TimeMS: at, ExpiresMS: at + 86_400_000, Keys: must(s.Keys("release", ""))}
	f, err := signWith(s, kb)
	if err != nil || len(f.Sigs) != 2 || f.Sigs[0].Alg != release.AlgES256 || f.Sigs[1].Alg != release.AlgSLHDSA {
		t.Fatalf("signed %+v (%v)", f.Sigs, err)
	}
	if _, err := release.VerifyKeys(f, roots, now(), release.Seen{}); err != nil {
		t.Errorf("the two signatures do not verify under the printed roots: %v", err)
	}
	// pq-check signs with both halves and checks them under the public file.
	pubPath := write(t, filepath.Join(dir, "root-9.pem"), pubs)
	hw := "file:" + ec + "+age:" + filepath.Join(dir, "pq", must(pqName(c))+".identity") + ":" + filepath.Join(dir, "pq", must(pqName(c))+".age")
	if out := call(t, pqCheck, "-key", hw, "-public", pubPath); !bytes.Contains(out, []byte("both halves sign")) {
		t.Errorf("pq-check printed %q", out)
	}
	// Under another key's public halves it fails.
	other := write(t, filepath.Join(dir, "other.pem"), must(release.PublicPEM(must(release.GenerateSigner()), "root-8")))
	if pqCheck([]string{"-key", hw, "-public", other}) == nil {
		t.Error("pq-check passed under another key")
	}
	// A file with one half is no proof.
	classical, _, _ := bytes.Cut(pubs, []byte("-----END PUBLIC KEY-----\n"))
	half := write(t, filepath.Join(dir, "half.pem"), append(classical, []byte("-----END PUBLIC KEY-----\n")...))
	if pqCheck([]string{"-key", hw, "-public", half}) == nil {
		t.Error("pq-check passed with one half")
	}
	// Another hardware does not open it.
	write(t, filepath.Join(dir, "pq", must(pqName(c))+".identity"), []byte("age1yubikey1other\n"))
	if _, err := pqOf(c, ""); err == nil {
		t.Error("another identity opened the half")
	}
}

// TestPQNewForAServer: -out - writes the half as PEM for systemd-creds,
// and CLASSICAL+slh:FILE signs with it.
func TestPQNewForAServer(t *testing.T) {
	dir := t.TempDir()
	ec := ecFile(t, dir)
	pubPath := filepath.Join(dir, "channel.pem")
	secret := call(t, pqNew, "-key", "file:"+ec, "-out", "-", "-public", pubPath)
	pq := write(t, filepath.Join(dir, "channel-pq.pem"), secret)
	s, err := signer("file:" + ec + "+slh:" + pq)
	if err != nil {
		t.Fatal(err)
	}
	pubs, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	halves, err := release.ReadHalves(pubs)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.PublicKeys()
	for _, alg := range release.Required {
		if !bytes.Equal(got[alg], halves[alg]) {
			t.Errorf("the public key of algorithm %d is not the signer's", alg)
		}
	}
	// A classical key where the SLH-DSA half belongs is refused.
	if _, err := signer("file:" + ec + "+slh:" + ec); err == nil {
		t.Error("a P-256 key served as the post-quantum half")
	}
	if out := call(t, pqCheck, "-key", "file:"+ec+"+slh:"+pq, "-public", pubPath); !bytes.Contains(out, []byte("both halves sign")) {
		t.Errorf("pq-check printed %q", out)
	}
	if pqNew([]string{"-key", "file:" + ec, "-out", "-"}) == nil {
		t.Error("-out - without -public")
	}
}
