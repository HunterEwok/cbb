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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
	asked := testPassphrase(t, "the owner's passphrase")
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
	if *asked != 2 {
		t.Errorf("pq-new asked for the passphrase %d times, not twice", *asked)
	}
	// Under the hardware's wrap, the half is sealed with the passphrase.
	sealedFile, _ := os.ReadFile(filepath.Join(dir, "pq", must(pqName(must(classicalSigner("file:"+ec))))+".age"))
	if _, inner, _ := bytes.Cut(sealedFile, []byte("\n")); !sealed(inner) || bytes.Contains(sealedFile, []byte("PRIVATE KEY")) {
		t.Error("the half under the hardware's wrap is not sealed with the passphrase")
	}
	// The file alone is no key: it is encrypted.
	entries, _ := os.ReadDir(filepath.Join(dir, "pq"))
	if len(entries) != 4 {
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
	// The half is opened for each signature, not before: its public key
	// is in HASH.pub.
	opened := 0
	prevD := ageDecrypt
	ageDecrypt = func(identity, file string) ([]byte, error) { opened++; return prevD(identity, file) }
	t.Cleanup(func() { ageDecrypt = prevD })
	lazy, err := pqOf(c, "")
	if err != nil || opened != 0 {
		t.Fatalf("pqOf opened the half %d times (%v)", opened, err)
	}
	for i := range 2 {
		if _, err := signWith(release.Signer{c, lazy}, release.Channel{V: 1, Type: release.TypeChannel, Channel: "stable", Seq: uint64(i + 1),
			TimeMS: now().UnixMilli(), ExpiresMS: now().UnixMilli() + 86_400_000, Release: "0.6.0", ReleaseSHA256: strings.Repeat("ab", 32)}); err != nil {
			t.Fatal(err)
		}
	}
	if opened != 2 {
		t.Errorf("two signatures opened the half %d times", opened)
	}
	if *asked != 2 {
		t.Errorf("the run asked for the passphrase again: %d", *asked)
	}
	// A new run with a wrong passphrase signs nothing, and says so.
	cachedPassphrase = nil
	readPassphrase = func(string) ([]byte, error) { return []byte("not the passphrase"), nil }
	before := opened
	if _, err := signWith(release.Signer{c, lazy}, kb0()); !errors.Is(err, errPassphrase) {
		t.Errorf("a wrong passphrase: %v", err)
	}
	if opened != before {
		t.Error("a wrong passphrase asked the hardware")
	}
	// Another half's pq-new takes the same passphrase, asked once.
	cachedPassphrase = nil
	n := 0
	readPassphrase = func(string) ([]byte, error) { n++; return []byte("another passphrase"), nil }
	ec2 := ecFile(t, t.TempDir())
	if pqNew([]string{"-key", "file:" + ec2, "-to", "age1yubikey1test", "-identity", id}) == nil || n != 1 {
		t.Errorf("pq-new sealed a half with another passphrase (asked %d)", n)
	}
	readPassphrase = func(string) ([]byte, error) { return []byte("the owner's passphrase"), nil }
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
	if _, err := openHalf(c, ""); err == nil {
		t.Error("another identity opened the half")
	}
	if _, err := signWith(release.Signer{c, lazy}, kb); err == nil {
		t.Error("a signature opened the half with another identity")
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
	// Never to a terminal.
	prev := isTerminal
	isTerminal = func(*os.File) bool { return true }
	err = pqNew([]string{"-key", "file:" + ec, "-out", "-", "-public", filepath.Join(dir, "p2.pem")})
	isTerminal = prev
	if err == nil {
		t.Error("pq-new wrote the private half to a terminal")
	}
	// -out FILE: a new file only its owner reads.
	half := filepath.Join(dir, "status-pq.pem")
	call(t, pqNew, "-key", "file:"+ec, "-out", half, "-public", filepath.Join(dir, "status.pem"))
	if st, err := os.Stat(half); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Errorf("the half's file: %v, %v", st.Mode(), err)
	}
	if pqNew([]string{"-key", "file:" + ec, "-out", half, "-public", filepath.Join(dir, "status.pem")}) == nil {
		t.Error("pq-new replaced a half's file")
	}
	if out := call(t, pqCheck, "-key", "file:"+ec+"+slh:"+half, "-public", filepath.Join(dir, "status.pem")); !bytes.Contains(out, []byte("both halves sign")) {
		t.Errorf("pq-check printed %q", out)
	}
}

func TestCutPaths(t *testing.T) {
	for _, c := range []struct {
		arg, id, file string
		windows, ok   bool
	}{
		{"/a/b.identity:/a/b.age", "/a/b.identity", "/a/b.age", false, true},
		{`C:\a\b.identity:C:\a\b.age`, `C:\a\b.identity`, `C:\a\b.age`, true, true},
		{`b.identity:d:\b.age`, "b.identity", `d:\b.age`, true, true},
		{`C:\a\b.identity`, "", "", true, false},
		{"b.identity", "", "", false, false},
	} {
		id, file, ok := cutPaths(c.arg, c.windows)
		if id != c.id || file != c.file || ok != c.ok {
			t.Errorf("cutPaths(%q, %v) = %q, %q, %v", c.arg, c.windows, id, file, ok)
		}
	}
}

// testPassphrase answers the passphrase prompts with p, at a low scrypt
// cost, and counts them.
// kb0 is a channel body to sign in the tests.
func kb0() release.Channel {
	return release.Channel{V: 1, Type: release.TypeChannel, Channel: "stable", Seq: 1,
		TimeMS: now().UnixMilli(), ExpiresMS: now().UnixMilli() + 86_400_000, Release: "0.6.0", ReleaseSHA256: strings.Repeat("ab", 32)}
}

func testPassphrase(t *testing.T, p string) *int {
	asked := 0
	prevRead, prevN := readPassphrase, sealLogN
	readPassphrase = func(string) ([]byte, error) { asked++; return []byte(p), nil }
	sealLogN = 10
	cachedPassphrase = nil
	t.Cleanup(func() { readPassphrase, sealLogN, cachedPassphrase = prevRead, prevN, nil })
	return &asked
}

// The passphrase seal: what one passphrase seals, another does not open,
// and the cost is read from the seal's line.
func TestSeal(t *testing.T) {
	testPassphrase(t, "a passphrase of the test")
	box, err := seal([]byte("right passphrase"), []byte("the half"), "name")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(box, []byte("cbb-pq-sealed v1 scrypt 10 8 1\n")) {
		t.Fatalf("the seal starts %q", box[:40])
	}
	if out, err := unseal([]byte("right passphrase"), box, "name"); err != nil || string(out) != "the half" {
		t.Fatalf("unseal: %q, %v", out, err)
	}
	if _, err := unseal([]byte("wrong passphrase"), box, "name"); !errors.Is(err, errPassphrase) {
		t.Errorf("a wrong passphrase: %v", err)
	}
	if _, err := unseal([]byte("right passphrase"), box, "another key"); err == nil {
		t.Error("the seal opened for another key")
	}
	raised := bytes.Replace(box, []byte("scrypt 10 "), []byte("scrypt 30 "), 1)
	if _, err := unseal([]byte("right passphrase"), raised, "name"); err == nil || errors.Is(err, errPassphrase) {
		t.Errorf("a cost out of range: %v", err)
	}
	if _, err := unseal([]byte("right passphrase"), box[:40], "name"); err == nil {
		t.Error("a seal cut short opened")
	}
}

// fetch reads a release file whole up to release.MaxFile, as every reader.
func TestFetchWholeFile(t *testing.T) {
	big := bytes.Repeat([]byte("a"), release.MaxFile)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(big) }))
	defer srv.Close()
	prev := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = prev }()
	got, err := fetch(srv.URL)
	if err != nil || len(got) != release.MaxFile {
		t.Errorf("fetched %d bytes of %d: %v", len(got), release.MaxFile, err)
	}
}
