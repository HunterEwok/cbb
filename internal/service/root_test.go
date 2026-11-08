// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
)

// testCA makes a CA as a phone does: a root with path length 1 when parent
// is nil, else an admin CA with path length 0 under it.
func testCA(t *testing.T, parent *group.CA) *group.CA {
	t.Helper()
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "cbb group root 2026-10-22"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	parentCert, parentKey := tmpl, crypto.Signer(key)
	if parent != nil {
		tmpl.Subject.CommonName = "cbb admin " + string(group.NewDeviceID())
		tmpl.MaxPathLen, tmpl.MaxPathLenZero = 0, true
		parentCert, parentKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &group.CA{Cert: c, Key: key}
}

// memberIn saves a computer's identity without CA keys, its certificate
// from issuer, in a new state directory.
func memberIn(t *testing.T, first, issuer *group.CA, roots ...*x509.Certificate) (string, *group.Identity) {
	t.Helper()
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := group.NewDeviceID()
	cert, err := issuer.IssueMember(dev, &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	id := &group.Identity{ID: dev, Key: key, Cert: cert, GroupCA: group.CA{Cert: first.Cert}, Roots: roots}
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	return dir, id
}

func sign(t *testing.T, first *x509.Certificate, body group.RecordBody, key crypto.Signer, chain ...*x509.Certificate) group.Record {
	t.Helper()
	body.Group, body.TimeMS = group.Tag(first), time.Now().UnixMilli()
	r := grouptest.Sign(t, body, key, chain...)
	return r
}

// TestRootHandover checks computers in a phone group whose root phone was
// lost and whose admin phone B claimed the group for a new root, under a
// root's settings without a waiting time: one holds the records when it
// starts, one gets them from it, and both talk to a computer the new root
// admitted.
func TestRootHandover(t *testing.T) {
	old, newRoot := testCA(t, nil), testCA(t, nil)
	adminB := testCA(t, old)
	holderDir, holder := memberIn(t, old, old)
	laterDir, later := memberIn(t, old, old)
	newDir, admitted := memberIn(t, old, newRoot, newRoot.Cert)

	g := old.Cert
	hk, lk, bk, nk := group.KeyHashOf(holder.Cert), group.KeyHashOf(later.Cert), group.KeyHashOf(adminB.Cert), group.KeyHashOf(admitted.Cert)
	noWait := int64(0)
	recs := group.NewRecords(g)
	if _, errs := recs.AddAll([]group.Record{
		sign(t, g, group.RecordBody{Type: group.RecordSettings, TakeoverDelayMS: &noWait}, old.Key),
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: string(holder.ID), Name: "holder", Role: group.RoleMember, Caps: group.AllCaps, Key: &hk}, old.Key),
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: string(later.ID), Name: "later", Role: group.RoleMember, Caps: group.AllCaps, Key: &lk}, old.Key),
		// The lost root recorded B as an admin phone, which may claim the group.
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: string(group.NewDeviceID()), Name: "phone B", Role: group.RolePhone, Key: &group.KeyHash{2}, Admin: &bk,
			Powers: authority.Powers, Commands: authority.Commands}, old.Key),
		sign(t, g, group.RecordBody{Type: group.RecordClaim, Root: newRoot.Cert.Raw}, adminB.Key, adminB.Cert),
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: string(admitted.ID), Name: "new", Role: group.RoleMember, Caps: group.AllCaps, Key: &nk}, newRoot.Key),
	}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := recs.Save(holderDir); err != nil {
		t.Fatal(err)
	}

	var h hub
	a := startIn(t, &h, &testService{name: "holder", dir: holderDir, os: group.OSLinux})
	// The control socket answers before the group has started.
	waitFor(t, "the holder keeps the new root", func() bool {
		id, err := group.Load(holderDir)
		return err == nil && len(id.Roots) == 1
	})
	b := startIn(t, &h, &testService{name: "later", dir: laterDir, os: group.OSLinux})
	waitFor(t, "the later one has the new root", func() bool {
		id, err := group.Load(laterDir)
		return err == nil && len(id.Roots) == 1 && id.Root().Equal(newRoot.Cert)
	})
	c := startIn(t, &h, &testService{name: "new", dir: newDir, os: group.OSLinux})
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" connected to both", func() bool { return len(s.status(t).Peers) == 2 })
	}
}
