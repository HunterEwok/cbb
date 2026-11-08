// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/tpmkey"
	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
)

// TestTPMEvidence checks that a computer whose member key is in a TPM with
// an EK certificate proves it to the group's root: the root records the
// key as hardware from the hello, then as proven once the TPM opened the
// root's credential. Without the maker's certificate it stays hardware.
func TestTPMEvidence(t *testing.T) {
	tpmtest.Start(t)
	roots := tpmtest.ProvisionEK(t)
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	tpmRoots = roots
	t.Cleanup(func() { tpmRoots = nil })

	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	id, err := group.Load(deck.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := id.Key.(*tpmkey.Key); !ok {
		t.Fatal("the deck's member key is not in the TPM")
	}
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
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	tpmRoots = tpmtest.OtherRoots(t)
	t.Cleanup(func() { tpmRoots = nil })

	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	if id, err := group.Load(deck.dir); err != nil {
		t.Fatal(err)
	} else if _, ok := id.Key.(*tpmkey.Key); !ok {
		t.Fatal("the deck's member key is not in the TPM")
	}
	waitFor(t, "deck is listed as hardware", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "deck" {
				return d.Store == group.StoreHardware
			}
		}
		return false
	})
}

// TestTPMCredentialOnlyFromRoot checks that a device takes TPM credentials
// to open only from the group's root, by its key, one at a time.
func TestTPMCredentialOnlyFromRoot(t *testing.T) {
	now := time.Now()
	root, err := group.Create(now)
	if err != nil {
		t.Fatal(err)
	}
	recs := group.NewRecords(root.GroupCA.Cert)
	key := group.KeyHashOf(root.Cert)
	r := grouptest.Sign(t, group.RecordBody{Type: group.RecordDevice, Group: group.Tag(root.GroupCA.Cert), Device: string(root.ID),
		Name: "pi", Role: group.RoleMember, Caps: group.AllCaps, Key: &key, HoldsRoot: true, TimeMS: now.UnixMilli()}, root.GroupCA.Key)
	if _, errs := recs.AddAll([]group.Record{r}); len(errs) > 0 {
		t.Fatal(errs)
	}
	other, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := group.NewDeviceID()
	member, err := root.GroupCA.IssueMember(dev, &other.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{records: recs}
	cred := node.Evidence{Format: node.EvidenceTPMCredential, Key: node.EvidenceMember}
	notRoot := "not the group's root"
	for name, c := range map[string]struct {
		peer group.DeviceID
		cert *x509.Certificate
	}{
		"a member":                 {dev, member},
		"a member named the root":  {root.ID, member},
		"the root's key elsewhere": {dev, root.Cert},
	} {
		if err := s.tpmCredential(c.peer, c.cert, cred); err == nil || !strings.Contains(err.Error(), notRoot) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The root gets as far as the TPM, which this device has none of here.
	if err := s.tpmCredential(root.ID, root.Cert, cred); err == nil || strings.Contains(err.Error(), notRoot) {
		t.Errorf("the root: %v", err)
	}
	s.tpmOpening.Lock()
	if err := s.tpmCredential(root.ID, root.Cert, cred); err == nil || !strings.Contains(err.Error(), "opens another") {
		t.Errorf("while the TPM opens one: %v", err)
	}
	s.tpmOpening.Unlock()
	if err := (&Service{}).tpmCredential(root.ID, root.Cert, cred); err == nil || !strings.Contains(err.Error(), notRoot) {
		t.Errorf("in no group: %v", err)
	}
}

// TestRootInTPMCountsAsFiles checks that a computer root whose member key
// is in the TPM still counts as keys in a file, since its group CA key is
// a file: cbb new starts the group at the level files, the devices list
// says files, and the level hardware is refused.
func TestRootInTPMCountsAsFiles(t *testing.T) {
	tpmtest.Start(t)
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)

	var h hub
	pi := startService(t, &h, "pi")
	m, err := pi.do(t, control.Header{Op: control.OpNew}, "")
	if err != nil {
		t.Fatal(err)
	}
	id, err := group.Load(pi.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := id.Key.(*tpmkey.Key); !ok {
		t.Fatal("the root's member key is not in the TPM")
	}
	if m.Status == nil || m.Status.KeyLevel != LevelFiles {
		t.Fatalf("the new group's key level: %+v", m.Status)
	}
	for _, d := range pi.devices(t) {
		if d.Name == "pi" && d.Store != group.StoreFile {
			t.Errorf("the root's keys are listed as %s", d.Store)
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpKeyLevel, Value: LevelHardware}, ""); err == nil {
		t.Error("a root with its CA key in a file set the level hardware")
	}
}
