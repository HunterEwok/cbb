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

// TestRootInTPMCountsAsFiles checks that a computer root whose member key
// is in the TPM still counts as keys in a file, since its group CA key is
// a file: cbb new starts the group at the level files, the devices list
// says files, and the level hardware is refused.
func TestRootInTPMCountsAsFiles(t *testing.T) {
	tpmtest.Start(t)
	sim := tpmOnlyFor(t)
	var h hub
	pi := startEnv(t, &h, "pi", sim)
	m, err := pi.do(t, control.Header{Op: control.OpNew}, "")
	if err != nil {
		t.Fatal(err)
	}
	keyInTPM(t, pi)
	if m.Status == nil || m.Status.KeyLevel != "files" {
		t.Fatalf("the new group's key level: %+v", m.Status)
	}
	for _, d := range pi.devices(t) {
		if d.Name == "pi" && d.Store != group.StoreFile {
			t.Errorf("the root's keys are listed as %s", d.Store)
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpKeyLevel, Value: "hardware"}, ""); err == nil {
		t.Error("a root with its CA key in a file set the level hardware")
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

// keyInTPM checks that identity.json keeps s's member key as the TPM's
// blob, and no key.
func keyInTPM(t *testing.T, s *testService) {
	t.Helper()
	var f struct {
		Key    []byte          `json:"key"`
		KeyTPM json.RawMessage `json:"key_tpm"`
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Key) != 0 || len(f.KeyTPM) == 0 {
		t.Fatalf("%s's member key is not in the TPM: identity.json keeps the key %d bytes, the TPM blob %q (%v)", s.name, len(f.Key), f.KeyTPM, err)
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
