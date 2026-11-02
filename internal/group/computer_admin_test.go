// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
)

// adminCAFor issues an admin CA for the key pub of the device dev, as the
// root phone does when it makes a computer an admin.
func adminCAFor(t *testing.T, root *CA, cn string, pub *ecdsa.PublicKey) *x509.Certificate {
	t.Helper()
	cert, err := create(&x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             root.Cert.NotBefore,
		NotAfter:              root.Cert.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, root.Cert, pub, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// computerAdmin is a computer of the phone group pg that the root made an
// admin.
func computerAdmin(t *testing.T, pg phoneGroup) *Identity {
	t.Helper()
	id, err := adminIdentity(t, pg, nil).WithAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if id, err = id.WithAdminCA(adminCAFor(t, pg.root, AdminName(id.ID), PublicKey(id.AdminKey)).Raw, t0); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestComputerAdmin checks a computer that the root phone makes an admin:
// it gets an admin key, takes an admin CA for it, signs with it, issues
// its own certificate from it, and keeps both across a save and a load.
func TestComputerAdmin(t *testing.T) {
	pg := newPhoneGroup(t)
	plain := adminIdentity(t, pg, nil)
	if ca, _ := plain.Signer(); ca != nil {
		t.Error("a computer without an admin CA can sign")
	}
	pending, err := plain.WithAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pending.WithAdminKey(); err == nil {
		t.Error("got a second admin key")
	}
	if ca, _ := pending.Signer(); ca != nil {
		t.Error("a computer with only an admin key can sign")
	}
	dir := t.TempDir()
	if err := pending.Save(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(dir); err != nil || got.AdminKey == nil || !SameKey(got.AdminKey, pending.AdminKey.Public()) || got.AdminCA != nil {
		t.Fatalf("the admin key was not kept: %v", err)
	}

	cn := AdminName(pending.ID)
	other := newPhoneGroup(t)
	key, _ := NewKey()
	for name, c := range map[string]*x509.Certificate{
		"another key":           adminCAFor(t, pg.root, cn, &key.PublicKey),
		"another device":        adminCAFor(t, pg.root, AdminName(NewDeviceID()), PublicKey(pending.AdminKey)),
		"another group's root":  adminCAFor(t, other.root, cn, PublicKey(pending.AdminKey)),
		"from an admin CA":      adminCAFor(t, pg.a, cn, PublicKey(pending.AdminKey)),
		"a member certificate":  member(t, pg.root),
		"the root's own":        pg.root.Cert,
		"another admin's admin": pg.a.Cert,
	} {
		if _, err := pending.WithAdminCA(c.Raw, t0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := pending.WithAdminCA([]byte("junk"), t0); err == nil {
		t.Error("accepted a corrupt admin CA")
	}

	admin, err := pending.WithAdminCA(adminCAFor(t, pg.root, cn, PublicKey(pending.AdminKey)).Raw, t0)
	if err != nil {
		t.Fatal(err)
	}
	ca, chain := admin.Signer()
	if ca == nil || !ca.Cert.Equal(admin.AdminCA) || len(chain) != 1 || !chain[0].Equal(admin.AdminCA) {
		t.Fatal("the admin computer does not sign with its admin CA")
	}
	if !admin.Issuer.Equal(admin.AdminCA) || admin.Cert.CheckSignatureFrom(admin.AdminCA) != nil {
		t.Error("its member certificate is not from its admin CA")
	}
	if err := admin.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil || got.AdminCA == nil || !got.AdminCA.Equal(admin.AdminCA) {
		t.Fatalf("the admin CA was not kept: %v", err)
	}
	r, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(pg.root.Cert), TimeMS: nextTime(), Device: string(NewDeviceID()), Name: "deck",
		Role: RoleFull, Key: &KeyHash{1}}, ca.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	recs := NewRecords(pg.root.Cert)
	mustAdd(t, recs, adminComputer(t, pg.root, admin.Cert, "pc", KeyHashOf(admin.AdminCA), false))
	if ok, err := recs.Add(r); !ok || err != nil || len(recs.Devices()) != 2 {
		t.Errorf("a record the admin computer signed: %v, %v", ok, err)
	}

	// Neither the root nor a member of a legacy group gets an admin key.
	if _, err := newGroup(t).WithAdminKey(); err == nil {
		t.Error("the root got an admin key")
	}
	if _, err := join(t, newLegacyGroup(t), false, t0).WithAdminKey(); err == nil {
		t.Error("a legacy group's member got an admin key")
	}
}

// TestComputerRoot checks a group a computer created: the root makes a
// member an admin with IssueAdmin, and the admin takes the iPhone CA and
// serves the shortcut with it; a member that is no admin never holds it.
func TestComputerRoot(t *testing.T) {
	root := newGroup(t)
	m := join(t, root, false, t0)
	if !m.NeedsAdminKey() || m.IsAdmin() || m.ServesPhone() || m.IsRoot() {
		t.Fatal("a new member is not a plain member waiting for an admin key")
	}
	pending, err := m.WithAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pending.WithPhoneCA(*root.PhoneCA, t0); err == nil {
		t.Error("a member that is no admin took the iPhone CA")
	}
	key, _ := NewKey()
	if _, err := (&CA{Cert: root.GroupCA.Cert}).IssueAdmin(pending.ID, PublicKey(pending.AdminKey), t0); err == nil {
		t.Error("issued an admin CA without the root key")
	}
	if _, err := root.PhoneCA.IssueAdmin(pending.ID, &key.PublicKey, t0); err == nil {
		t.Error("the iPhone CA issued an admin CA")
	}
	adminCA, err := root.GroupCA.IssueAdmin(pending.ID, PublicKey(pending.AdminKey), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminCA(adminCA, root.GroupCA.Cert); err != nil || adminCA.Subject.CommonName != AdminName(pending.ID) {
		t.Fatalf("the admin CA: %v, %q", err, adminCA.Subject.CommonName)
	}
	admin, err := pending.WithAdminCA(adminCA.Raw, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !admin.IsAdmin() || admin.IsRoot() || admin.ServesPhone() {
		t.Error("the new admin is not an admin without the iPhone CA")
	}
	if _, err := admin.WithPhoneCA(CA{Cert: root.PhoneCA.Cert}, t0); err == nil {
		t.Error("took the iPhone CA without its key")
	}
	if _, err := admin.WithPhoneCA(root.GroupCA, t0); err == nil {
		t.Error("took the root as the iPhone CA")
	}
	serving, err := admin.WithPhoneCA(*root.PhoneCA, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !serving.ServesPhone() || serving.Phone.VerifyHostname(PhoneName) != nil || !SameKey(serving.Key, serving.Phone.PublicKey) {
		t.Error("the admin does not serve the shortcut with its own clipboardbridge.local certificate")
	}
	dir := t.TempDir()
	if err := serving.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil || !got.ServesPhone() || !SameKey(got.PhoneCA.Key, root.PhoneCA.Key.Public()) || got.AdminCA == nil {
		t.Fatalf("the admin's iPhone CA was not kept: %v", err)
	}
	if back := serving.WithoutPhoneCA(); back.ServesPhone() || back.Check() != nil || !back.IsAdmin() {
		t.Error("an admin without the iPhone CA does not check")
	}
}

// TestTakenOver checks the identity of an admin computer that takes the
// group over: it holds the new root's key, is the root and no admin any
// more, keeps that across a save, and is no root once the group moves on.
func TestTakenOver(t *testing.T) {
	root := newGroup(t)
	m, err := join(t, root, false, t0).WithAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	adminCA, err := root.GroupCA.IssueAdmin(m.ID, PublicKey(m.AdminKey), t0)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := m.WithAdminCA(adminCA.Raw, t0)
	if err == nil {
		admin, err = admin.WithPhoneCA(*root.PhoneCA, t0)
	}
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewRootCA(t0)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewRootCA(t0)
	// The claim's new root waits in the identity, across a save, until
	// the claim takes effect.
	if _, err := root.WithClaim(next); err == nil {
		t.Error("the root holds a claim")
	}
	// A member that is no admin claims only with the recovery key, which
	// signs its claim; the identity keeps the new root alike.
	if _, err := m.WithClaim(next); err != nil {
		t.Errorf("a member with the recovery key cannot hold its claim: %v", err)
	}
	if _, err := admin.WithClaim(&CA{Cert: next.Cert}); err == nil {
		t.Error("held a claim without its root key")
	}
	if _, err := admin.WithClaim(&CA{Cert: next.Cert, Key: other.Key}); err == nil {
		t.Error("held a claim with another key")
	}
	claiming, err := admin.WithClaim(next)
	if err != nil {
		t.Fatal(err)
	}
	cdir := t.TempDir()
	if err := claiming.Save(cdir); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(cdir); err != nil || got.Claim == nil || !got.Claim.Cert.Equal(next.Cert) || !SameKey(got.Claim.Key, next.Key.Public()) || got.IsRoot() {
		t.Fatalf("the claim was not kept: %v", err)
	}
	if dropped, err := claiming.WithClaim(nil); err != nil || dropped.Claim != nil {
		t.Errorf("a cancelled claim is not dropped: %v", err)
	}
	if took, err := claiming.TakenOver(claiming.Claim, []*x509.Certificate{next.Cert}, t0); err != nil || took.Claim != nil || !took.IsRoot() {
		t.Errorf("the claim's root did not become the root: %v", err)
	}
	if _, err := admin.TakenOver(next, []*x509.Certificate{other.Cert}, t0); err == nil {
		t.Error("took the group over though the records lead to another root")
	}
	if _, err := m.TakenOver(next, []*x509.Certificate{next.Cert}, t0); err == nil {
		t.Error("a member that is no admin took the group over")
	}
	took, err := admin.TakenOver(next, []*x509.Certificate{next.Cert}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if took.Cert.CheckSignatureFrom(next.Cert) != nil || took.Issuer != nil {
		t.Error("the new root keeps a member certificate from its admin CA, which a joiner rejects")
	}
	if !took.IsRoot() || took.AdminCA != nil || took.AdminKey != nil || took.NeedsAdminKey() {
		t.Error("the admin that took the group over is not its root")
	}
	if ca, chain := took.Signer(); ca == nil || !ca.Cert.Equal(next.Cert) || chain != nil {
		t.Error("the new root does not sign with its root key")
	}
	dir := t.TempDir()
	if err := took.Save(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(dir); err != nil || !got.IsRoot() || !SameKey(got.RootKey, next.Key.Public()) {
		t.Fatalf("the root key was not kept: %v", err)
	}
	renewed, changed, err := took.Renew(took.Cert.NotAfter.Add(-memberRenewBefore + time.Hour))
	if err != nil || !changed || renewed.Cert.CheckSignatureFrom(next.Cert) != nil || renewed.Issuer != nil {
		t.Errorf("the new root does not renew its own certificate from itself: %v", err)
	}
	if _, err := admin.WithRoots([]*x509.Certificate{next.Cert}); err != nil {
		t.Errorf("an admin does not follow the new root: %v", err)
	}
	moved, err := took.WithRoots([]*x509.Certificate{next.Cert, other.Cert})
	if err != nil || moved.IsRoot() || moved.RootKey != nil {
		t.Errorf("after another takeover the device is still root: %v", err)
	}
}

// TestComputerAdminRenews checks that an admin computer renews its own
// certificate and those of its peers from its admin CA, which the peers
// take with the issuer.
func TestComputerAdminRenews(t *testing.T) {
	pg := newPhoneGroup(t)
	admin := computerAdmin(t, pg)
	peer := adminIdentity(t, pg, pg.a)
	if c, _, err := admin.RenewMember(peer.Cert, t0.AddDate(0, 6, 0)); c != nil || err != nil {
		t.Errorf("renewed half a year in: %v, %v", c, err)
	}
	at := t0.AddDate(1, 6, 0)
	cert, issuer, err := admin.RenewMember(peer.Cert, at)
	if err != nil || cert == nil || !issuer.Equal(admin.AdminCA) {
		t.Fatalf("RenewMember = %v, %v, %v", cert, issuer, err)
	}
	next, err := peer.WithCertFrom(cert.Raw, issuer.Raw)
	if err != nil || !next.Issuer.Equal(admin.AdminCA) {
		t.Fatalf("the peer did not take it: %v", err)
	}
	if c, _, err := adminIdentity(t, pg, nil).RenewMember(peer.Cert, at); c != nil || err != nil {
		t.Errorf("a computer that is no admin renewed: %v, %v", c, err)
	}

	own, changed, err := admin.Renew(at)
	if err != nil || !changed || !own.Issuer.Equal(admin.AdminCA) || !own.Cert.NotAfter.After(admin.Cert.NotAfter) {
		t.Fatalf("Renew = %v, %v", changed, err)
	}
	if err := own.Check(); err != nil {
		t.Error(err)
	}
	if _, changed, _ := admin.Renew(t0.Add(time.Hour)); changed {
		t.Error("renewed its own certificate early")
	}
}

// TestRootDeviceAndAdmitted checks the records' root phone, the device of
// the root's own record that says it holds the root, and that removing an
// admin keeps the devices it admitted.
func TestRootDeviceAndAdmitted(t *testing.T) {
	pg := newPhoneGroup(t)
	tag := Tag(pg.root.Cert)
	rootPhone, aPhone, deck := NewDeviceID(), NewDeviceID(), NewDeviceID()
	k1, k2, k3, ka := KeyHash{1}, KeyHash{2}, KeyHash{3}, KeyHashOf(pg.a.Cert)
	sign := func(body RecordBody, ca *CA, chain ...*x509.Certificate) Record {
		body.Group, body.TimeMS = tag, nextTime()
		r, err := signRecord(body, ca.Key, chain...)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	recs := NewRecords(pg.root.Cert)
	if recs.RootDevice() != "" {
		t.Error("an empty set has a root phone")
	}
	if _, errs := recs.AddAll([]Record{
		// A root's record of a device without holds_root names no root.
		sign(RecordBody{Type: RecordDevice, Device: string(deck), Name: "deck", Role: RoleFull, Key: &k3}, pg.root),
	}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if recs.RootDevice() != "" {
		t.Error("a record without holds_root names the root's device")
	}
	if _, errs := recs.AddAll([]Record{
		sign(RecordBody{Type: RecordDevice, Device: string(rootPhone), Name: "root", Role: RolePhone, Key: &k1, HoldsRoot: true}, pg.root),
		sign(RecordBody{Type: RecordDevice, Device: string(aPhone), Name: "a", Role: RolePhone, Key: &k2, Admin: &ka, Powers: authority.Powers, Commands: authority.Commands}, pg.root),
		sign(RecordBody{Type: RecordDevice, Device: string(deck), Name: "deck", Role: RoleFull, Key: &k3}, pg.a, pg.a.Cert),
		// An admin's record of its own device that says it holds the root
		// counts for nothing.
		sign(RecordBody{Type: RecordDevice, Device: string(aPhone), Name: "a", Role: RolePhone, Key: &k2, Admin: &ka, HoldsRoot: true}, pg.a, pg.a.Cert),
	}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if got := recs.RootDevice(); got != rootPhone {
		t.Errorf("RootDevice = %q, want %q", got, rootPhone)
	}
	if dev, key := recs.RootMember(); dev != rootPhone || key != k1 {
		t.Errorf("RootMember = %q, %v", dev, key)
	}
	for _, d := range recs.Devices() {
		if d.ID == aPhone && (d.AdminKey == nil || *d.AdminKey != ka || !d.May(authority.PowerTakeover)) {
			t.Error("the admin phone's admin key and powers are not listed")
		}
	}
	mustAdd(t, recs, sign(RecordBody{Type: RecordRevoke, Keys: []KeyHash{k2, ka}}, pg.root))
	if got := names(recs.Devices()); got != "deck root" {
		t.Errorf("devices after the admin's removal %q, want deck root", got)
	}
}
