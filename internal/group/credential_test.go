// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

// credentialGroup is a phone group with a root phone, an admin phone, two
// admin computers, a computer whose admin CA was removed, a plain computer
// and a removed one, with the member keys of each.
type credentialGroup struct {
	pg      phoneGroup
	records []Record
	keys    map[string]*ecdsa.PrivateKey // member keys by name
	hashes  map[string]KeyHash
	pcOne   *CA // an admin computer's admin CA
}

// memberWithKey is member with its key.
func memberWithKey(t *testing.T, ca *CA) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueMember(NewDeviceID(), &key.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newCredentialGroup(t *testing.T) credentialGroup {
	t.Helper()
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	cg := credentialGroup{pg: pg, keys: map[string]*ecdsa.PrivateKey{}, hashes: map[string]KeyHash{}}
	certs := map[string]*x509.Certificate{}
	for _, n := range []string{"root", "phone", "one", "two", "demoted", "plain", "removed"} {
		c, k := memberWithKey(t, pg.root)
		certs[n], cg.keys[n], cg.hashes[n] = c, k, KeyHashOf(c)
	}
	rootDev := DeviceID(certs["root"].Subject.CommonName)
	rk := cg.hashes["root"]
	own, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: 1, Device: string(rootDev), Name: "root phone", Role: RolePhone, Key: &rk, HoldsRoot: true}, pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	cg.pcOne = adminCA(t, pg.root)
	two, gone := adminCA(t, pg.root), adminCA(t, pg.root)
	cg.records = []Record{
		own,
		adminRecord(t, g, pg.root, nil, certs["phone"], "admin phone", KeyHashOf(pg.a.Cert)),
		computerAdminRecord(t, pg, certs["one"], "pc one", KeyHashOf(cg.pcOne.Cert)),
		computerAdminRecord(t, pg, certs["two"], "pc two", KeyHashOf(two.Cert)),
		computerAdminRecord(t, pg, certs["demoted"], "demoted pc", KeyHashOf(gone.Cert)),
		deviceRecord(t, g, pg.root, nil, certs["plain"], "plain pc", 1),
		deviceRecord(t, g, pg.root, nil, certs["removed"], "removed pc", 1),
		revokeRecord(t, g, pg.root, nil, []KeyHash{KeyHashOf(gone.Cert), cg.hashes["removed"]}),
	}
	return cg
}

func (cg credentialGroup) set(t *testing.T) *Records {
	t.Helper()
	s := NewRecords(cg.pg.root.Cert)
	if _, errs := s.AddAll(cg.records); len(errs) != 0 {
		t.Fatal(errs)
	}
	return s
}

func (cg credentialGroup) names(t *testing.T, ks []KeyHash) []string {
	t.Helper()
	var out []string
	for _, k := range ks {
		for n, h := range cg.hashes {
			if h == k {
				out = append(out, n)
			}
		}
	}
	return out
}

// TestCredentialLists checks what a phone group's credentials list: the
// hubs in their order, the admin computers first, then the phones with
// the root's own first among them; the admins other than the root, without the one whose admin CA was
// removed; and every device that was not removed.
func TestCredentialLists(t *testing.T) {
	cg := newCredentialGroup(t)
	l := cg.set(t).CredentialLists()
	hubs := cg.names(t, l.Hubs)
	if len(hubs) != 4 || hubs[2] != "root" || hubs[3] != "phone" || !slices.Contains(hubs[:2], "one") || !slices.Contains(hubs[:2], "two") {
		t.Errorf("hubs = %v", hubs)
	}
	admins := cg.names(t, l.Admins)
	slices.Sort(admins)
	if !slices.Equal(admins, []string{"one", "phone", "two"}) {
		t.Errorf("admins = %v", admins)
	}
	members := cg.names(t, l.Members)
	slices.Sort(members)
	if !slices.Equal(members, []string{"demoted", "one", "phone", "plain", "root", "two"}) {
		t.Errorf("members = %v", members)
	}
}

// period is a period of the group and its key.
type period struct {
	c   Credential
	b   *CredentialBody
	key *ecdsa.PrivateKey
}

func newPeriod(t *testing.T, cg credentialGroup, root *CA, version uint64, now time.Time) period {
	t.Helper()
	key, _ := NewKey()
	tag, err := NewPeriodTag()
	if err != nil {
		t.Fatal(err)
	}
	c, err := SignPeriod(Tag(cg.pg.root.Cert), tag, &key.PublicKey, version, now, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Open()
	if err != nil {
		t.Fatal(err)
	}
	return period{c, b, key}
}

// servers signs a server credential for the period with each member key
// named, and returns them with the server keys by name.
func (cg credentialGroup) servers(t *testing.T, p period, names ...string) ([]Credential, map[string]*ecdsa.PrivateKey) {
	t.Helper()
	var cs []Credential
	keys := map[string]*ecdsa.PrivateKey{}
	for _, n := range names {
		k, _ := NewKey()
		c, err := SignServer(p.b, &k.PublicKey, 1, cg.keys[n])
		if err != nil {
			t.Fatal(err)
		}
		cs, keys[n] = append(cs, c), k
	}
	return cs, keys
}

// TestCredentialLifecycle checks what a member keeps: the period of the
// current root only; server credentials of members for that period; the
// hubs' credential of the period key; the members' credential of the
// period key or of an admin it lists; newer versions only; and a new
// period dropping the old one's credentials.
func TestCredentialLifecycle(t *testing.T) {
	cg := newCredentialGroup(t)
	recs := cg.set(t)
	root := cg.pg.root
	s := NewCredentials(root.Cert)
	now := t0
	p := newPeriod(t, cg, root, 10, now)
	if fresh, errs := s.Add(root.Cert, recs.IsMember, []Credential{p.c}); len(fresh) != 1 || len(errs) != 0 {
		t.Fatalf("the period: %d fresh, %v", len(fresh), errs)
	}
	other := newRoot(t)
	if _, errs := s.Add(root.Cert, recs.IsMember, []Credential{newPeriod(t, cg, other, 11, now).c}); len(errs) != 1 {
		t.Error("a period another root signed was taken")
	}
	srv, skeys := cg.servers(t, p, "root", "phone", "one", "plain")
	rogue, _ := cg.servers(t, p, "removed")
	if fresh, errs := s.Add(root.Cert, recs.IsMember, append(srv, rogue...)); len(fresh) != 4 || len(errs) != 1 {
		t.Errorf("server credentials: %d fresh, %v", len(fresh), errs)
	}
	if k, ok := s.Server(cg.hashes["one"]); !ok || k != KeyHashOf(selfCert(t, skeys["one"])) {
		t.Error("the server key of pc one is not kept")
	}
	if m, ok := s.MemberOfServer(KeyHashOf(selfCert(t, skeys["plain"]))); !ok || m != cg.hashes["plain"] {
		t.Error("the pseudonym does not lead to its member")
	}
	l := recs.CredentialLists()
	hubKeys, adminKeys := s.ServerKeys(l.Hubs), s.ServerKeys(l.Admins)
	if len(hubKeys) != 3 || len(adminKeys) != 2 {
		t.Fatalf("%d hubs and %d admins with server keys", len(hubKeys), len(adminKeys))
	}
	hubs, err := SignHubs(p.b, hubKeys, adminKeys, 1, p.key)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := SignHubs(p.b, hubKeys, adminKeys, 2, skeys["one"])
	if fresh, errs := s.Add(root.Cert, recs.IsMember, []Credential{hubs, forged}); len(fresh) != 1 || len(errs) != 1 {
		t.Errorf("hubs: %d fresh, %v", len(fresh), errs)
	}
	_, hb, _ := s.Hubs()
	if len(hb.Hubs) != 4 || len(hb.Admins) != 4 || s.ListStale(hb.Hubs, hubKeys, true) || s.ListStale(hb.Admins, adminKeys, false) {
		t.Errorf("the hubs' credential: %d hubs, %d admins, or it is stale", len(hb.Hubs), len(hb.Admins))
	}
	if !s.ListStale(hb.Hubs, hubKeys[:2], true) {
		t.Error("a list that names a key no longer wanted is not stale")
	}
	memberKeys := s.ServerKeys(l.Members)
	byAdmin, _ := SignMembers(p.b, memberKeys, 5, skeys["one"])
	byPlain, _ := SignMembers(p.b, memberKeys, 6, skeys["plain"])
	if fresh, errs := s.Add(root.Cert, recs.IsMember, []Credential{byAdmin, byPlain}); len(fresh) != 1 || len(errs) != 1 {
		t.Errorf("members: %d fresh, %v", len(fresh), errs)
	}
	older, _ := SignMembers(p.b, memberKeys, 4, p.key)
	if fresh, _ := s.Add(root.Cert, recs.IsMember, []Credential{older}); len(fresh) != 0 {
		t.Error("an older members' credential was taken")
	}
	if len(s.All()) != 7 {
		t.Errorf("it keeps %d credentials", len(s.All()))
	}

	dir := t.TempDir()
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	again, err := LoadCredentials(dir, root.Cert, root.Cert, recs.IsMember)
	if err != nil || len(again.All()) != 7 {
		t.Fatalf("loaded %v, %v", again, err)
	}

	if s.PeriodStale(root.Cert, recs.IsMember, now.Add(PeriodRenew-time.Hour)) {
		t.Error("a period not yet due is stale")
	}
	if !s.PeriodStale(root.Cert, recs.IsMember, now.Add(PeriodRenew+time.Hour)) {
		t.Error("a period due is not stale")
	}
	if !s.PeriodStale(other.Cert, recs.IsMember, now) {
		t.Error("a period of the root before is not stale for the new root")
	}
	gone := func(k KeyHash) bool { return k != cg.hashes["plain"] && recs.IsMember(k) }
	if !s.PeriodStale(root.Cert, gone, now) {
		t.Error("a period whose member left is not stale")
	}

	next := newPeriod(t, cg, root, 20, now)
	if fresh, _ := s.Add(root.Cert, recs.IsMember, []Credential{next.c}); len(fresh) != 1 {
		t.Fatal("the next period was not taken")
	}
	if all := s.All(); len(all) != 1 {
		t.Errorf("after the next period it keeps %d credentials", len(all))
	}
	if fresh, _ := s.Add(root.Cert, recs.IsMember, append([]Credential{hubs}, srv...)); len(fresh) != 0 {
		t.Error("credentials of the period before were taken")
	}
}

func selfCert(t *testing.T, k *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	c, err := ServerCertificate(k)
	if err != nil {
		t.Fatal(err)
	}
	return c.Leaf
}

// TestCheckPresented checks what a server takes: a hubs' credential with a
// members' credential that the period key or a listed admin signed, and a
// period credential of the same period.
func TestCheckPresented(t *testing.T) {
	cg := newCredentialGroup(t)
	p := newPeriod(t, cg, cg.pg.root, 1, t0)
	admin, _ := NewKey()
	stranger, _ := NewKey()
	adminHash := KeyHashOf(selfCert(t, admin))
	hubs, _ := SignHubs(p.b, []KeyHash{{1}}, []KeyHash{adminHash}, 1, p.key)
	members, _ := SignMembers(p.b, []KeyHash{{1}, {2}}, 1, admin)
	got, err := CheckPresented([]Credential{hubs, members, p.c}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tag != p.b.Tag || got.Signer != KeyHashOf(selfCert(t, p.key)) || got.Members == nil || !bytes.Equal(got.PeriodRoot, cg.pg.root.Cert.RawSubjectPublicKeyInfo) {
		t.Errorf("presented = %+v", got)
	}
	forged, _ := SignMembers(p.b, []KeyHash{{1}}, 1, stranger)
	other := newPeriod(t, cg, cg.pg.root, 2, t0)
	otherMembers, _ := SignMembers(other.b, []KeyHash{{1}}, 1, other.key)
	for name, cs := range map[string][]Credential{
		"members by a stranger":    {hubs, forged},
		"members of another":       {hubs, otherMembers},
		"a period of another":      {hubs, other.c},
		"no hubs":                  {members},
		"two hubs' credentials":    {hubs, hubs},
		"nothing":                  nil,
		"a server credential sent": {hubs, must(SignServer(p.b, &admin.PublicKey, 1, admin))},
	} {
		if _, err := CheckPresented(cs, t0); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if _, err := CheckPresented([]Credential{hubs}, t0.Add(PeriodLifetime)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired: %v", err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// TestServerCertificate checks the certificate a device registers with on
// a server: its server key only, with no device and no group.
func TestServerCertificate(t *testing.T) {
	key, _ := NewKey()
	c, err := ServerCertificate(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DeviceOf(c.Leaf); err == nil || len(c.Leaf.DNSNames) != 0 || c.Leaf.Subject.CommonName != ServerCertificateName {
		t.Errorf("the server certificate names %v %v", c.Leaf.Subject, c.Leaf.DNSNames)
	}
	if len(c.Certificate) != 1 {
		t.Error("a chain follows")
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if !bytes.Equal(c.Leaf.RawSubjectPublicKeyInfo, spki) {
		t.Error("another key")
	}
}

type credentialVectors struct {
	GroupCA   []byte          `json:"group_ca"`
	Records   []Record        `json:"records"`
	Lists     CredentialLists `json:"lists"`
	Period    Credential      `json:"period"`
	Servers   []Credential    `json:"servers"`
	Hubs      Credential      `json:"hubs"`
	Members   Credential      `json:"members"`
	NowMS     int64           `json:"now_ms"`
	Pseudonym string          `json:"pseudonym"` // of the first hub's server key
	Bad       []badSet        `json:"bad"`
}

type badSet struct {
	Name string       `json:"name"`
	Set  []Credential `json:"set"`
}

// TestGoCredentialVectors checks a phone group's records in v:2, the lists
// its credentials must hold, a period with its server credentials, its
// hubs' and members' credentials, and sets a server refuses (docs/protocol.md,
// section 18).
func TestGoCredentialVectors(t *testing.T) {
	var v credentialVectors
	{
		cg := newCredentialGroup(t)
		s := cg.set(t)
		l := s.CredentialLists()
		p := newPeriod(t, cg, cg.pg.root, 1000, t0)
		srv, skeys := cg.servers(t, p, "root", "phone", "one", "two", "demoted", "plain")
		creds := NewCredentials(cg.pg.root.Cert)
		creds.Add(cg.pg.root.Cert, s.IsMember, append([]Credential{p.c}, srv...))
		hubs, _ := SignHubs(p.b, creds.ServerKeys(l.Hubs), creds.ServerKeys(l.Admins), 1001, p.key)
		members, _ := SignMembers(p.b, creds.ServerKeys(l.Members), 1002, skeys["one"])
		byPlain, _ := SignMembers(p.b, creds.ServerKeys(l.Members), 1003, skeys["plain"])
		stranger := newPeriod(t, cg, newRoot(t), 1000, t0)
		strangerHubs, _ := SignHubs(stranger.b, nil, nil, 1, stranger.key)
		v = credentialVectors{GroupCA: cg.pg.root.Cert.Raw, Records: cg.records, Lists: l,
			Period: p.c, Servers: srv, Hubs: hubs, Members: members, NowMS: t0.Add(time.Hour).UnixMilli(),
			Pseudonym: Pseudonym(creds.ServerKeys(l.Hubs)[0]),
			Bad: []badSet{
				{"a members' credential that a plain member signed", []Credential{hubs, byPlain}},
				{"a members' credential with another period's hubs", []Credential{strangerHubs, members}},
				{"a period of another period", []Credential{hubs, stranger.c}},
				{"no hubs' credential", []Credential{members}},
			}}
	}
	writeV2Vectors(t, "v2-credentials.json", v)
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) != 0 {
		t.Fatal(errs)
	}
	l := s.CredentialLists()
	if !slices.Equal(l.Hubs, v.Lists.Hubs) || !slices.Equal(l.Admins, v.Lists.Admins) || !slices.Equal(l.Members, v.Lists.Members) {
		t.Errorf("CredentialLists = %+v, the file has %+v", l, v.Lists)
	}
	creds := NewCredentials(ca)
	all := append([]Credential{v.Period, v.Hubs, v.Members}, v.Servers...)
	if fresh, errs := creds.Add(ca, s.IsMember, all); len(fresh) != len(all) || len(errs) != 0 {
		t.Fatalf("%d of %d taken, %v", len(fresh), len(all), errs)
	}
	_, hb, _ := creds.Hubs()
	if got := Pseudonym(hb.Hubs[0]); got != v.Pseudonym || !slices.Equal(hb.Hubs[:len(l.Hubs)], creds.ServerKeys(l.Hubs)) {
		t.Errorf("the first hub is %s, the file has %s", got, v.Pseudonym)
	}
	now := time.UnixMilli(v.NowMS)
	if _, err := CheckPresented([]Credential{v.Hubs, v.Members, v.Period}, now); err != nil {
		t.Error(err)
	}
	for _, b := range v.Bad {
		if _, err := CheckPresented(b.Set, now); err == nil {
			t.Errorf("%s: taken", b.Name)
		}
	}
}

// failingSigner is a signer whose key or signature fails.
type failingSigner struct {
	pub     crypto.PublicKey
	signErr error
}

func (s failingSigner) Public() crypto.PublicKey { return s.pub }
func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.signErr
}

// A credential is not signed with a key that does not marshal, a signer
// that fails, or a body that breaks the rules.
func TestCredentialSigningRefusals(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	notAKey := struct{}{}
	if _, err := SignPeriod("0123456789abcdef", "0123456789abcdef", notAKey, 1, now, key); err == nil {
		t.Error("a period with a key that does not marshal was signed")
	}
	p := &CredentialBody{Group: "0123456789abcdef", Tag: "0123456789abcdef", ExpiresMS: now.Add(time.Hour).UnixMilli()}
	if _, err := SignServer(p, notAKey, 1, key); err == nil {
		t.Error("a server key that does not marshal was signed")
	}
	good, err := SignPeriod("0123456789abcdef", "0123456789abcdef", &key.PublicKey, 1, now, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := good.Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignCredential(*body, failingSigner{pub: notAKey}); err == nil {
		t.Error("a signer whose key does not marshal signed")
	}
	if _, err := SignCredential(*body, failingSigner{pub: &key.PublicKey, signErr: errors.New("no")}); err == nil {
		t.Error("a signer that fails signed")
	}
	bad := *body
	bad.Type = "nothing"
	if _, err := SignCredential(bad, key); err == nil {
		t.Error("a body of no type was signed")
	}
}
