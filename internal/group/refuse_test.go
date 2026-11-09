// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/clip"
)

// TestIdentityCheckRefusals breaks one part of a member's identity at a
// time: Check refuses each.
func TestIdentityCheckRefusals(t *testing.T) {
	admin := newGroup(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := newRoot(t)
	cases := []struct {
		name   string
		break_ func(id *Identity)
		want   string
	}{
		{"device ID", func(id *Identity) { id.ID = "x" }, ""},
		{"no key", func(id *Identity) { id.Key = nil }, "P-256"},
		{"later roots beside the group CA's key", func(id *Identity) { id.GroupCA.Key = admin.GroupCA.Key; id.Roots = append(id.Roots, other.Cert) }, "later roots"},
		{"a root key with no root", func(id *Identity) { id.RootKey = other.Key }, "root key"},
		{"no certificate", func(id *Identity) { id.Cert = nil }, "missing"},
		{"a CA for a certificate", func(id *Identity) { id.Cert = id.GroupCA.Cert }, "is a CA"},
		{"an issuer of another group", func(id *Identity) { id.Issuer = other.Cert }, "admin CA"},
		{"an admin CA with no admin key", func(id *Identity) { id.AdminCA = other.Cert }, "no admin key"},
		{"a P-384 admin key", func(id *Identity) { id.AdminKey = p384 }, "P-256"},
	}
	for _, c := range cases {
		id := join(t, admin, t0)
		c.break_(id)
		err := id.Check()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// TestSignRemovalSeen checks that a removal Sign makes names in seen the
// highest seq of every signer, its own one before the removal included.
func TestSignRemovalSeen(t *testing.T) {
	pg := newPhoneGroup(t)
	root := pg.root.Cert
	s := NewRecords(root)
	mustAdd(t, s, adminRecord(t, root, pg.root, nil, member(t, pg.a), "phone", KeyHashOf(pg.a.Cert)))
	mustAdd(t, s, deviceRecord(t, root, pg.a, []*x509.Certificate{pg.a.Cert}, member(t, pg.a), "pc", 2))
	gone := member(t, pg.a)
	r, err := s.Sign(RecordBody{Type: RecordRevoke, TimeMS: nextTime(), Keys: []KeyHash{KeyHashOf(gone)}}, pg.b.Key, pg.b.Cert)
	if err != nil {
		t.Fatal(err)
	}
	b, err := authority.ParseBody(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	signer := KeyHashOf(pg.b.Cert)
	want := map[KeyHash]int64{KeyHashOf(root): 1, KeyHashOf(pg.a.Cert): 1, signer: 0}
	if len(b.Seen) != len(want) {
		t.Fatalf("seen %+v, want %v", b.Seen, want)
	}
	for i, e := range b.Seen {
		if n, ok := want[e.Key]; !ok || n != e.Seq {
			t.Errorf("seen %+v, want %v", e, want)
		}
		if i > 0 && b.Seen[i-1].Key.String() >= e.Key.String() {
			t.Error("seen is not sorted")
		}
	}
	if !containsSeen(b.Seen, signer) {
		t.Error("the signer is not in its own seen")
	}
}

func containsSeen(seen []authority.Seen, k KeyHash) bool {
	for _, e := range seen {
		if e.Key == k {
			return true
		}
	}
	return false
}

// TestCredentialRefusals opens credentials that were changed, and the
// period a set keeps for its root only.
func TestCredentialRefusals(t *testing.T) {
	cg := newCredentialGroup(t)
	root := cg.pg.root
	p := newPeriod(t, cg, root, 1, t0)
	bad := p.c
	bad.Sig = append([]byte(nil), p.c.Sig...)
	bad.Sig[len(bad.Sig)-1] ^= 1
	if _, err := bad.Open(); err == nil {
		t.Error("a credential with a changed signature opens")
	}
	junk := p.c
	junk.Body = []byte("{")
	if _, err := junk.Open(); err == nil {
		t.Error("a credential with a body that is no JSON opens")
	}
	nokey := p.c
	nokey.Key = []byte{1}
	if _, err := nokey.Open(); err == nil {
		t.Error("a credential with a bad key opens")
	}
	s := NewCredentials(root.Cert)
	if _, _, ok := s.Period(root.Cert); ok {
		t.Error("an empty set has a period")
	}
	recs := cg.set(t)
	if _, errs := s.Add(root.Cert, recs.IsMember, []Credential{p.c}); len(errs) != 0 {
		t.Fatal(errs)
	}
	if c, b, ok := s.Period(root.Cert); !ok || b.Version != 1 || string(c.Sig) != string(p.c.Sig) {
		t.Error("the period kept is not given back")
	}
	if _, _, ok := s.Period(newRoot(t).Cert); ok {
		t.Error("a period is given for another root")
	}
}

// TestCheckCopyFromAnAdminsMember checks a copy whose origin an admin CA
// certified, and refuses one whose key the records do not name or whose
// certificate is not its origin's.
func TestCheckCopyFromAnAdminsMember(t *testing.T) {
	pg := newPhoneGroup(t)
	root := pg.root.Cert
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewDeviceID()
	cert, err := pg.a.IssueMember(dev, &key.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(root)
	mustAdd(t, s, adminRecord(t, root, pg.root, nil, member(t, pg.a), "phone", KeyHashOf(pg.a.Cert)))
	mustAdd(t, s, deviceRecord(t, root, pg.a, []*x509.Certificate{pg.a.Cert}, cert, "pc", 2))
	id := &Identity{ID: dev, Key: key, Cert: cert, Issuer: pg.a.Cert}
	readers := []clip.Reader{{ID: string(dev), Seal: sealKeyOf(t)}}
	if err := s.CheckCopy(sealedFrom(t, id, readers), t0); err != nil {
		t.Fatalf("a copy of an admin's member: %v", err)
	}
	unknown := &Identity{ID: NewDeviceID(), Key: key, Issuer: pg.a.Cert}
	if unknown.Cert, err = pg.a.IssueMember(unknown.ID, &key.PublicKey, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCopy(sealedFrom(t, unknown, readers), t0); err == nil || !strings.Contains(err.Error(), "records name") {
		t.Errorf("a copy of a device the records do not name: %v", err)
	}
	c := sealedFrom(t, id, readers)
	c.Issuer = []byte{1, 2, 3}
	if err := s.CheckCopy(c, t0); err == nil {
		t.Error("a copy with an issuer that does not parse")
	}
}

// TestIssueAdminRefusals: only a root that holds its key certifies a P-256
// admin key, within its lifetime.
func TestIssueAdminRefusals(t *testing.T) {
	pg := newPhoneGroup(t)
	key, _ := NewKey()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.root.IssueAdmin(NewDeviceID(), &key.PublicKey, t0); err != nil {
		t.Fatalf("a good admin CA: %v", err)
	}
	cases := []struct {
		name string
		ca   *CA
		dev  DeviceID
		pub  *ecdsa.PublicKey
		now  time.Time
	}{
		{"device ID", pg.root, "x", &key.PublicKey, t0},
		{"an admin CA", pg.a, NewDeviceID(), &key.PublicKey, t0},
		{"no root key", &CA{Cert: pg.root.Cert}, NewDeviceID(), &key.PublicKey, t0},
		{"no key", pg.root, NewDeviceID(), nil, t0},
		{"a P-384 key", pg.root, NewDeviceID(), &p384.PublicKey, t0},
		{"the clock", pg.root, NewDeviceID(), &key.PublicKey, t0.AddDate(caYears+1, 0, 0)},
	}
	for _, c := range cases {
		if _, err := c.ca.IssueAdmin(c.dev, c.pub, c.now); err == nil {
			t.Errorf("%s: an admin CA was issued", c.name)
		}
	}
}

// TestRefusedChains refuses no chain and a member of another group's admin.
func TestRefusedChains(t *testing.T) {
	pg := newPhoneGroup(t)
	s := NewRecords(pg.root.Cert)
	if err := s.Refused(nil); err == nil {
		t.Error("no chain is taken")
	}
	stranger := adminCA(t, newRoot(t))
	if err := s.Refused([]*x509.Certificate{member(t, stranger), stranger.Cert}); err == nil || !strings.Contains(err.Error(), "not from a root") {
		t.Errorf("a member of another group's admin: %v", err)
	}
	if err := s.Refused([]*x509.Certificate{member(t, stranger)}); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Errorf("a member with no issuer: %v", err)
	}
}

// TestSealCommandToABadKey refuses to seal to a key that is not one.
func TestSealCommandToABadKey(t *testing.T) {
	pg := newPhoneGroup(t)
	now := int64(1_800_000_000_000)
	b := CommandBody{Type: CommandPaste, Group: Tag(pg.root.Cert), By: NewDeviceID(), To: NewDeviceID(), ID: NewCommandID(), TimeMS: now, ExpiresMS: now + CommandLifetime.Milliseconds()}
	b.Mode, b.Kind, b.Text = PasteByClipboard, "text", "hi"
	if _, err := SealCommand(b, []byte{1, 2, 3}); err == nil {
		t.Error("a command was sealed to a key that is not one")
	}
	sb, err := SealCommand(b, sealKeyOf(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Open(nil); err == nil {
		t.Error("a sealed command opens with no secret")
	}
}
