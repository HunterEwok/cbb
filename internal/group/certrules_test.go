// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// A key that is not P-256, an admin CA the root cannot issue and an admin
// CA that does not chain to the root are each refused.
func TestCertificateRules(t *testing.T) {
	if PublicKey(nil) != nil {
		t.Error("a nil signer has a public key")
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if PublicKey(ed) != nil {
		t.Error("an Ed25519 key passes as P-256")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if PublicKey(p384) != nil {
		t.Error("a P-384 key passes as P-256")
	}

	now := time.Unix(1_800_000_000, 0)
	root, err := NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dev := NewDeviceID()
	if _, err := root.IssueAdmin("x", &admin.PublicKey, now); err == nil {
		t.Error("an admin CA for a bad device ID")
	}
	if _, err := root.IssueAdmin(dev, &p384.PublicKey, now); err == nil {
		t.Error("an admin CA for a P-384 key")
	}
	if _, err := root.IssueAdmin(dev, &admin.PublicKey, root.Cert.NotBefore.Add(-time.Hour)); err == nil {
		t.Error("an admin CA before the root's lifetime")
	}
	keyless := &CA{Cert: root.Cert}
	if _, err := keyless.IssueAdmin(dev, &admin.PublicKey, now); err == nil {
		t.Error("an admin CA without the root's key")
	}
	groupCA, err := NewGroupCA(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groupCA.IssueAdmin(dev, &admin.PublicKey, now); err == nil {
		t.Error("a group CA of path length 0 issued an admin CA")
	}
	if _, err := root.IssueMember("x", &admin.PublicKey, now); err == nil {
		t.Error("a member certificate for a bad device ID")
	}

	adminCA, err := root.IssueAdmin(dev, &admin.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminCA(adminCA, root.Cert); err != nil {
		t.Fatalf("a good admin CA: %v", err)
	}
	other, err := NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminCA(adminCA, other.Cert); err == nil {
		t.Error("an admin CA of another root is taken")
	}
	if err := CheckAdminCA(adminCA, groupCA.Cert); err == nil {
		t.Error("a root that certifies no admin CAs is taken")
	}
	if err := CheckAdminCA(root.Cert, root.Cert); err == nil {
		t.Error("a root passes as an admin CA")
	}
	if err := checkRoot(groupCA.Cert); err == nil {
		t.Error("a group CA of path length 0 passes as a new root")
	}
}
