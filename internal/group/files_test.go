// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/keyseal"
	"github.com/HunterEwok/cbb/internal/sekey"
)

// TestLoadRejectsDamagedParts damages each part of an identity file in
// turn: Load refuses the file rather than start with part of an identity.
func TestLoadRejectsDamagedParts(t *testing.T) {
	admin := newGroup(t)
	dir := t.TempDir()
	if err := admin.Save(dir); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	var f identityFile
	if err := json.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	junk := []byte("junk")
	for _, tt := range []struct {
		name   string
		change func(f *identityFile)
	}{
		{"a damaged certificate", func(f *identityFile) { f.Cert = junk }},
		{"a damaged issuer", func(f *identityFile) { f.Issuer = junk }},
		{"a damaged group CA", func(f *identityFile) { f.GroupCA = junk }},
		{"a damaged group CA key", func(f *identityFile) { f.GroupCAKey = junk }},
		{"a damaged root", func(f *identityFile) { f.Roots = [][]byte{junk} }},
		{"a damaged root key", func(f *identityFile) { f.RootKey = junk }},
		{"a damaged admin key", func(f *identityFile) { f.AdminKey = junk }},
		{"a damaged admin CA", func(f *identityFile) { f.AdminCA = junk }},
		{"a damaged previous certificate", func(f *identityFile) { f.PrevCert = junk }},
		{"a damaged previous issuer", func(f *identityFile) { f.PrevIssuer = junk }},
		{"a damaged claim", func(f *identityFile) { f.Claim = junk }},
		{"a claim key without its claim", func(f *identityFile) { f.ClaimKey = junk }},
		{"a key in a Secure Enclave that is not there", func(f *identityFile) { f.Key, f.KeySE = nil, junk }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bad := f
			tt.change(&bad)
			data, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseIdentity(data); err == nil {
				t.Error("the damaged identity loaded")
			}
		})
	}
}

// TestStaleAdminCA tells an admin CA of the group's current root from one
// that another root signed.
func TestStaleAdminCA(t *testing.T) {
	admin := newGroup(t)
	other := newGroup(t)
	id := *join(t, admin, t0)
	if id.StaleAdminCA() {
		t.Error("a device without an admin CA has a stale one")
	}
	id.AdminCA = admin.GroupCA.Cert
	if id.StaleAdminCA() {
		t.Error("the current root's certificate is stale")
	}
	id.AdminCA = other.GroupCA.Cert
	if !id.StaleAdminCA() {
		t.Error("an admin CA from another root is not stale")
	}
}

// TestSealerWithoutHardware: with TPM support off nothing is sealed, and a
// blob that names no hardware, or a Secure Enclave this machine lacks, does
// not open.
func TestSealerWithoutHardware(t *testing.T) {
	t.Setenv(TPMEnv, "off")
	if got := WhyNotHardware(); !strings.Contains(got, TPMEnv) {
		t.Errorf("WhyNotHardware() = %q, want it to name %s", got, TPMEnv)
	}
	if b, err := (Sealer{}).Seal([]byte("secret")); b != nil || err != nil {
		t.Errorf("Seal with the TPM off = %v, %v; want nil, nil", b, err)
	}
	if _, err := (Sealer{}).Unseal(&keyseal.Blob{}); err == nil {
		t.Error("a blob without hardware opened")
	}
	if !sekeyAvailable() {
		if _, err := (Sealer{}).Unseal(&keyseal.Blob{SE: []byte("junk")}); err == nil {
			t.Error("a Secure Enclave blob opened on a machine without one")
		}
	}
}

// TestLoadSealSecretRejectsBadFiles: a seal key file that does not decode,
// has another version, holds no valid secret or names hardware that is not
// there stops the load.
func TestLoadSealSecretRejectsBadFiles(t *testing.T) {
	t.Setenv(TPMEnv, "off")
	dir := t.TempDir()
	secret, err := LoadSealSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadSealSecret(dir)
	if err != nil || string(again) != string(secret) {
		t.Fatalf("the seal secret changed on the second load: %v", err)
	}
	files := map[string]string{
		"not JSON":        "{",
		"another version": `{"v":2}`,
		"no secret":       `{"v":1}`,
	}
	if !sekeyAvailable() {
		files["a Secure Enclave that is not there"] = `{"v":1,"se":"anVuaw=="}`
	}
	for name, data := range files {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, SealKeyFileName), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSealSecret(dir); err == nil {
				t.Error("the bad seal key file loaded")
			}
		})
	}
}

func sekeyAvailable() bool { return sekey.Available() }

// TestCheckCopyRejectsDamagedCertificates: a copy whose certificate or
// issuer does not parse is refused before its chain is looked at.
func TestCheckCopyRejectsDamagedCertificates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "go-copy-checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v copyChecks
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	for _, r := range v.Records {
		mustAdd(t, s, r)
	}
	now := time.UnixMilli(v.NowMS)
	for _, c := range v.Copies {
		if !c.OK {
			continue
		}
		bad := *c.Event
		bad.Cert = []byte("junk")
		if err := s.CheckCopy(&bad, now); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Errorf("a damaged certificate: %v", err)
		}
		bad = *c.Event
		bad.Issuer = []byte("junk")
		if err := s.CheckCopy(&bad, now); err == nil || !strings.Contains(err.Error(), "issuer") {
			t.Errorf("a damaged issuer: %v", err)
		}
		return
	}
	t.Fatal("no copy the file accepts")
}

// TestLoadCredentialsRejectsBadFiles: a credentials file that does not
// decode, or cannot be read, stops the load; a missing one is empty.
func TestLoadCredentialsRejectsBadFiles(t *testing.T) {
	admin := newGroup(t)
	dir := t.TempDir()
	member := func(KeyHash) bool { return true }
	if s, err := LoadCredentials(dir, admin.GroupCA.Cert, admin.Root(), member); err != nil || len(s.All()) != 0 {
		t.Fatalf("a missing file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, CredentialsFileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(dir, admin.GroupCA.Cert, admin.Root(), member); err == nil {
		t.Error("a file that does not decode loaded")
	}
	unreadable := t.TempDir()
	if err := os.Mkdir(filepath.Join(unreadable, CredentialsFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(unreadable, admin.GroupCA.Cert, admin.Root(), member); err == nil {
		t.Error("a directory in place of the file loaded")
	}
}

// TestSmallErrors covers what the errors and hashes say at the edges.
func TestSmallErrors(t *testing.T) {
	if !strings.Contains(ErrStopped.Error(), "records only") {
		t.Errorf("ErrStopped says %q", ErrStopped.Error())
	}
	if PublicKeyHash("not a key") != (KeyHash{}) {
		t.Error("a value that is no key has a hash")
	}
}
