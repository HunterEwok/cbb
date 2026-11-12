// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Yubico's PIV attestation extensions.
var (
	oidFirmware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

func readCerts(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("roots", "attestation", name))
	if err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			return certs
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		certs = append(certs, c)
	}
}

func extension(c *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	return nil
}

// attestPool gives the chain from a YubiKey's attestation to Yubico's root.
func attestPool(t *testing.T) (roots, inter *x509.CertPool) {
	roots, inter = x509.NewCertPool(), x509.NewCertPool()
	for _, c := range readCerts(t, "yubico-root.pem") {
		roots.AddCert(c)
	}
	for _, c := range append(readCerts(t, "yubico-intermediates.pem"), readCerts(t, "yubikey-f9.pem")...) {
		inter.AddCert(c)
	}
	return roots, inter
}

// checkAttested checks that the attestation in name, under
// roots/attestation, proves that spki was made in the PIV slot on the
// YubiKey with serial, with the PIN and a touch for every signature.
func checkAttested(t *testing.T, name string, spki []byte, slot string, serial int64) {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(spki)
	if k, ok := pub.(*ecdsa.PublicKey); err != nil || !ok || k.Curve != elliptic.P256() {
		t.Fatalf("%s: not a P-256 key: %v", name, err)
	}
	certs := readCerts(t, name)
	if len(certs) != 1 {
		t.Fatalf("%s holds %d certificates", name, len(certs))
	}
	c := certs[0]
	if !bytes.Equal(c.RawSubjectPublicKeyInfo, spki) {
		t.Errorf("%s attests another key", name)
	}
	if want := "YubiKey PIV Attestation " + slot; c.Subject.CommonName != want {
		t.Errorf("%s: %q, want %q", name, c.Subject.CommonName, want)
	}
	roots, inter := attestPool(t)
	_, err = c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		CurrentTime: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		t.Errorf("%s does not lead to Yubico's root: %v", name, err)
	}
	if p := extension(c, oidPolicy); !bytes.Equal(p, []byte{3, 2}) {
		t.Errorf("%s: PIN and touch policies %x, want always (3) and always (2)", name, p)
	}
	var got int64
	if _, err := asn1.Unmarshal(extension(c, oidSerial), &got); err != nil || got != serial {
		t.Errorf("%s: serial %d (%v), want %d", name, got, err, serial)
	}
	if fw := extension(c, oidFirmware); !bytes.Equal(fw, []byte{5, 7, 4}) {
		t.Errorf("%s: firmware %v", name, fw)
	}
}

// The YubiKeys' serial numbers: the first holds root-1 and release key 1.
var yubikeys = []int64{36667388, 36667392}

// TestRootsAttested checks that each root key was made on a YubiKey,
// in slot 82, with the PIN and a touch for every signature
// (roots/README.md).
func TestRootsAttested(t *testing.T) {
	es := es256Roots()
	if len(es) != 2 {
		t.Fatalf("%d roots, want 2", len(es))
	}
	for i, spki := range es {
		checkAttested(t, "root-"+strconv.Itoa(i+1)+".pem", spki, "82", yubikeys[i])
	}
}

// TestReleaseKeysAttested checks the release keys in slot 83 of the same
// YubiKeys the same way. They are not pinned: keys.json certifies them,
// and roots/release-keys.pem only records them with their proof.
func TestReleaseKeysAttested(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("roots", "release-keys.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var keys [][]byte
	for b, rest := pem.Decode(data); b != nil; b, rest = pem.Decode(rest) {
		keys = append(keys, b.Bytes)
	}
	if len(keys) != 2 {
		t.Fatalf("%d release keys, want 2", len(keys))
	}
	for i, spki := range keys {
		checkAttested(t, "release-yubikey-"+strconv.Itoa(i+1)+".pem", spki, "83", yubikeys[i])
	}
}

// TestRootCopies checks the copies of the roots that the installers carry
// and that the Rust core reads.
func TestRootCopies(t *testing.T) {
	read := func(p string) string {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	pemText := strings.TrimSpace(string(rootsPEM))
	if !strings.Contains(read("packaging/get.sh"), "release_roots='"+pemText+"'") {
		t.Error("packaging/get.sh: release_roots is not roots/roots.pem")
	}
	b64 := regexp.MustCompile(`"(MF[A-Za-z0-9+/=]{100,})"|'(MF[A-Za-z0-9+/=]{100,})'`)
	// The phone kits ask the core and carry no copy.
	for _, p := range []string{
		"packaging/windows/get.ps1",
	} {
		var got [][]byte
		for _, m := range b64.FindAllStringSubmatch(read(p), -1) {
			der, err := base64.StdEncoding.DecodeString(m[1] + m[2])
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			got = append(got, der)
		}
		if !sameRoots(got) {
			t.Errorf("%s: the roots are not roots/roots.pem", p)
		}
	}
	// The Rust core reads roots/roots.pem itself (include_str!), for the
	// Rust cbb and for the phone kits through its release calls.
	if !strings.Contains(read("core/src/release.rs"), `include_str!("../../internal/release/roots/roots.pem")`) {
		t.Error("core/src/release.rs does not read roots/roots.pem")
	}
}

func es256Roots() [][]byte {
	var out [][]byte
	for _, r := range Roots {
		if r.Alg == AlgES256 {
			out = append(out, r.Key)
		}
	}
	return out
}

func sameRoots(got [][]byte) bool {
	es := es256Roots()
	if len(got) != len(es) {
		return false
	}
	for i := range got {
		if !bytes.Equal(got[i], es[i]) {
			return false
		}
	}
	return true
}

func TestCompleteRoots(t *testing.T) {
	var keys [3][]Key
	for i := range keys {
		s, err := GenerateSigner()
		if err != nil {
			t.Fatal(err)
		}
		if keys[i], err = s.Keys("root-"+strconv.Itoa(i+1), UseRoot); err != nil {
			t.Fatal(err)
		}
	}
	two := append(append([]Key{}, keys[0]...), keys[1]...)
	if err := CompleteRoots(two); err != nil {
		t.Fatalf("two whole roots: %v", err)
	}
	classicalOnly := func(k []Key) []Key {
		var out []Key
		for _, h := range k {
			if h.Alg == AlgES256 {
				out = append(out, h)
			}
		}
		return out
	}
	for name, roots := range map[string][]Key{
		"one root":              keys[0],
		"none":                  nil,
		"classical halves only": append(classicalOnly(keys[0]), classicalOnly(keys[1])...),
		"one root half missing": append(append([]Key{}, keys[0]...), classicalOnly(keys[1])...),
		"a half twice":          append(append([]Key{}, two...), keys[1][0]),
		"another root's half under its name": append(append([]Key{}, two...),
			Key{Alg: keys[2][0].Alg, Key: keys[2][0].Key, Name: "root-1", Use: UseRoot}),
	} {
		if CompleteRoots(roots) == nil {
			t.Errorf("%s: complete", name)
		}
	}
}

// TestPinnedRootsComplete runs in the release workflow before anything
// is built (CBB_RELEASE_TAG set): a release whose pinned roots lack a half
// would build devices that take no keys.json.
func TestPinnedRootsComplete(t *testing.T) {
	if os.Getenv("CBB_RELEASE_TAG") == "" {
		t.Skip("only for a release tag (CBB_RELEASE_TAG)")
	}
	if err := CompleteRoots(Roots); err != nil {
		t.Fatalf("roots/roots.pem: %v", err)
	}
}

// A root is its halves under one Name, one of each algorithm.
func TestParseRootsOneHalfEach(t *testing.T) {
	a, b := newSigner(t), newSigner(t)
	pem := func(s signer, name string) []byte {
		p, err := PublicPEM(s.key, name)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if r, err := ParseRoots(append(pem(a, "root-1"), pem(b, "root-2")...)); err != nil || len(r) != 4 {
		t.Fatalf("two roots: %d, %v", len(r), err)
	}
	if _, err := ParseRoots(append(pem(a, "root-1"), pem(b, "root-1")...)); err == nil {
		t.Error("two roots under one Name were read")
	}
}
