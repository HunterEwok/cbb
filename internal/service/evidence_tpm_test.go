// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
)

// TestTPMEvidence checks that a computer whose member key is in a TPM with
// an EK certificate proves it to the group's root: the root records the
// key as hardware from the hello, then as proven once the TPM opened the
// root's credential. Without the maker's certificate it stays hardware.
func TestTPMEvidence(t *testing.T) {
	tpmtest.Start(t)
	roots := tpmtest.ProvisionEK(t)
	var h hub
	pi, _ := tpmPair(t, &h, roots)
	store := func(s *testService, name string) string {
		for _, d := range s.devices(t) {
			if d.Name == name {
				return d.Store
			}
		}
		return ""
	}
	waitFor(t, "the root records the deck's key as proven", func() bool { return store(pi, "deck") == group.StoreProven })
}

// TestTPMEvidenceUnknownMaker checks that a TPM whose maker the root does
// not know leaves the key as hardware.
func TestTPMEvidenceUnknownMaker(t *testing.T) {
	tpmtest.Start(t)
	tpmtest.ProvisionEK(t)
	var h hub
	pi, _ := tpmPair(t, &h, tpmtest.OtherRoots(t))
	waitFor(t, "deck is listed as hardware", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "deck" {
				return d.Store == group.StoreHardware
			}
		}
		return false
	})
}

// TestRootKeyLevelFollowsItsStore checks the key level a computer root
// starts its group at on the records of 0.6, where the weakest of its keys
// decides: with a TPM both its member key and its root key are in the TPM
// (keys.json), so cbb new starts the group at the level hardware and lists
// the root's keys as hardware; with no TPM both keys are files, so the
// group starts at the level files, and the level hardware is refused.
func TestRootKeyLevelFollowsItsStore(t *testing.T) {
	tpmtest.Start(t)
	sim := tpmOnlyFor(t)
	var h hub
	pi := startEnv(t, &h, "pi", sim)
	m, err := pi.do(t, control.Header{Op: control.OpNew}, "")
	if err != nil {
		t.Fatal(err)
	}
	keyInTPM(t, pi)
	keyOfInTPM(t, pi, "root")
	if m.Status == nil || m.Status.KeyLevel != "hardware" {
		t.Fatalf("the new group's key level with its root key in the TPM: %+v", m.Status)
	}
	for _, d := range pi.devices(t) {
		if d.Name == "pi" && d.Store != group.StoreHardware {
			t.Errorf("the root's keys in the TPM are listed as %s", d.Store)
		}
	}

	files := startEnv(t, &h, "box", "CBB_TPM=off")
	m, err = files.do(t, control.Header{Op: control.OpNew}, "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Status == nil || m.Status.KeyLevel != "files" {
		t.Fatalf("the new group's key level with its root key in a file: %+v", m.Status)
	}
	for _, d := range files.devices(t) {
		if d.Name == "box" && d.Store != group.StoreFile {
			t.Errorf("the root's keys in files are listed as %s", d.Store)
		}
	}
	if _, err := files.do(t, control.Header{Op: control.OpKeyLevel, Value: "hardware"}, ""); err == nil {
		t.Error("a root with its keys in files set the level hardware")
	}
}

// tpmOnlyFor keeps swtpm, which takes one client at a time, for the one
// service whose cbb-helper is given the setting it returns: this test's
// process and the other services find no TPM, as the helper keeps its
// connection open.
func tpmOnlyFor(t *testing.T) string {
	t.Helper()
	sim := "CBB_TPM_SIMULATOR=" + os.Getenv("CBB_TPM_SIMULATOR")
	t.Setenv("CBB_TPM_SIMULATOR", "")
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	return sim
}

// tpmPair starts the root pi, which trusts the TPM makers roots and keeps
// its keys in files, and joins deck to it with its member key in swtpm.
func tpmPair(t *testing.T, h *hub, roots []*x509.Certificate) (pi, deck *testService) {
	t.Helper()
	sim := tpmOnlyFor(t)
	pi = startEnv(t, h, "pi", "CBB_TPM=off", "CBB_TEST_TPM_ROOTS="+rootsFile(t, roots))
	deck = startEnv(t, h, "deck", sim)
	pairWith(t, pi, deck)
	keyInTPM(t, deck)
	return pi, deck
}

// keyInTPM checks that keys.json (src/own.rs in cbb) keeps s's member key
// as the TPM's blob, and no key.
func keyInTPM(t *testing.T, s *testService) {
	t.Helper()
	var f struct {
		Member struct {
			PKCS8 string          `json:"pkcs8"`
			TPM   json.RawMessage `json:"tpm"`
		} `json:"member"`
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Member.PKCS8 != "" || len(f.Member.TPM) == 0 {
		t.Fatalf("%s's member key is not in the TPM: keys.json keeps the key %d characters, the TPM blob %q (%v)", s.name, len(f.Member.PKCS8), f.Member.TPM, err)
	}
}

// keyOfInTPM fails the test unless s's key which ("root", "admin") is in
// the TPM: keys.json keeps its TPM blob and no PKCS#8 (src/own.rs in cbb).
func keyOfInTPM(t *testing.T, s *testService, which string) {
	t.Helper()
	// keys.json holds its version "v" beside the keys, so each key is read
	// on its own.
	var f map[string]json.RawMessage
	var k struct {
		PKCS8 string          `json:"pkcs8"`
		TPM   json.RawMessage `json:"tpm"`
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &f); err == nil {
		err = json.Unmarshal(f[which], &k)
	}
	if err != nil || k.PKCS8 != "" || len(k.TPM) == 0 {
		t.Fatalf("%s's %s key is not in the TPM: keys.json keeps the key %d characters, the TPM blob %q (%v)", s.name, which, len(k.PKCS8), k.TPM, err)
	}
}

// rootsFile writes the certificates to a PEM file for the helper to read.
func rootsFile(t *testing.T, certs []*x509.Certificate) string {
	t.Helper()
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	f := filepath.Join(t.TempDir(), "tpm-roots.pem")
	if err := os.WriteFile(f, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}
