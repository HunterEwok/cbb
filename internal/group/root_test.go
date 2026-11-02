// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
)

// handover is the story of a claim (docs/protocol.md, section 10, "Handing the group
// over"): the root phone, which admitted a computer itself, is lost, and
// admin phone B claims the group with a new root of its own; once the claim
// takes effect, the new root lists B as the device that holds it and
// removes the lost phone.
type handover struct {
	pg          phoneGroup // root: the lost phone's; b: phone B's admin CA
	newRoot     *CA
	lost, b     *x509.Certificate // the phones' member certificates
	byRoot      *x509.Certificate // a computer the lost phone admitted
	byB         *x509.Certificate // a computer B admitted
	fromNew     *x509.Certificate // a computer the new root admitted
	before, all []Record          // the records before the claim, and all of them
}

func newHandover(t *testing.T) handover {
	t.Helper()
	pg := newPhoneGroup(t)
	h := handover{pg: pg, newRoot: newRoot(t)}
	g, bChain := pg.root.Cert, []*x509.Certificate{pg.b.Cert}
	h.lost, h.b, h.byRoot, h.byB, h.fromNew = member(t, pg.root), member(t, pg.b), member(t, pg.root), member(t, pg.b), member(t, h.newRoot)
	adminB := KeyHashOf(pg.b.Cert)
	h.before = []Record{
		ownRecord(t, pg.root, h.lost, "lost phone", RolePhone),
		adminRecord(t, g, pg.root, nil, h.b, "phone B", adminB),
		deviceRecord(t, g, pg.root, nil, h.byRoot, "by root", 2),
		deviceRecord(t, g, pg.b, bChain, h.byB, "by B", 3),
	}
	h.all = append(append([]Record(nil), h.before...),
		claimRecord(t, g, pg.b, bChain, h.newRoot.Cert),
		listedAgain(t, g, h.newRoot, h.b, "phone B", adminB),
		revokeRecord(t, g, h.newRoot, nil, []KeyHash{KeyHashOf(h.lost)}),
		deviceRecord(t, g, h.newRoot, nil, h.fromNew, "from new", 4),
	)
	return h
}

// listedAgain is the record a phone that took the group over signs for
// itself under its new root: it holds the root, and keeps its admin key.
func listedAgain(t *testing.T, group *x509.Certificate, signer *CA, cert *x509.Certificate, name string, admin KeyHash) Record {
	t.Helper()
	key := KeyHashOf(cert)
	r, err := signRecord(RecordBody{
		Type: RecordDevice, Group: Tag(group), TimeMS: nextTime(), Device: string(DeviceID(cert.Subject.CommonName)), Name: name, Role: RolePhone, Key: &key,
		Admin: &admin, Powers: authority.Powers, Commands: authority.Commands, HoldsRoot: true,
	}, signer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// records returns the set with every record of the story, on a clock past
// the claim's delay.
func (h handover) records(t *testing.T) *Records {
	t.Helper()
	s := NewRecords(h.pg.root.Cert)
	if _, errs := s.AddAll(h.all); len(errs) > 0 {
		t.Fatal(errs)
	}
	s.SetClock(afterDelay)
	return s
}

func TestRootHandover(t *testing.T) {
	h := newHandover(t)
	s := NewRecords(h.pg.root.Cert)
	if _, errs := s.AddAll(h.all); len(errs) > 0 {
		t.Fatal(errs)
	}
	// Until the delay passes, the claim waits and the lost phone is the
	// root.
	if len(s.Roots()) != 0 || s.RootDevice() != DeviceID(h.lost.Subject.CommonName) {
		t.Fatal("the claim took effect before its delay")
	}
	if st := s.State(); len(st.Claims) != 1 || st.Claims[0].State != "pending" {
		t.Fatalf("claims %+v, want one pending", st.Claims)
	}
	s.SetClock(afterDelay)
	if roots := s.Roots(); len(roots) != 1 || !roots[0].Equal(h.newRoot.Cert) {
		t.Fatalf("roots %v, want the new root", roots)
	}
	if got := names(s.Devices()); got != "by B by root from new phone B" {
		t.Errorf("devices %q, want by B, by root, phone B", got)
	}
	if got := admins(s.Devices()); got != "phone B" {
		t.Errorf("admins %q, want phone B", got)
	}
	if s.RootDevice() != DeviceID(h.b.Subject.CommonName) {
		t.Error("phone B does not hold the root")
	}
	if s.Refused([]*x509.Certificate{h.lost}) == nil {
		t.Error("the lost phone is not refused")
	}
	fromNew := h.fromNew
	for name, chain := range map[string][]*x509.Certificate{
		"the computer the old root admitted": {h.byRoot},
		"the computer B admitted":            {h.byB, h.pg.b.Cert},
		"phone B":                            {h.b, h.pg.b.Cert},
		"a device from the new root":         {fromNew},
	} {
		if err := s.Refused(chain); err != nil {
			t.Errorf("%s is refused: %v", name, err)
		}
	}
}

// TestRootHandoverThief checks what whoever holds the lost phone's root key
// can still do after the handover: cancel the claim, as the root always
// may, but nothing else that counts.
func TestRootHandoverThief(t *testing.T) {
	h := newHandover(t)
	s := h.records(t)
	g := h.pg.root.Cert
	thiefCA := adminCA(t, h.pg.root)
	thiefChain := []*x509.Certificate{thiefCA.Cert}
	stolen, viaThiefCA := member(t, h.pg.root), member(t, thiefCA)
	for _, r := range []Record{
		deviceRecord(t, g, h.pg.root, nil, stolen, "stolen", 9),
		deviceRecord(t, g, thiefCA, thiefChain, viaThiefCA, "via thief", 9),
		claimRecord(t, g, thiefCA, thiefChain, newRoot(t).Cert),
	} {
		mustAdd(t, s, r)
	}
	if roots := s.Roots(); len(roots) != 1 || !roots[0].Equal(h.newRoot.Cert) {
		t.Error("the thief moved the group to another root")
	}
	if got := names(s.Devices()); got != "by B by root from new phone B" {
		t.Errorf("devices %q after the thief's records", got)
	}
	for name, chain := range map[string][]*x509.Certificate{
		"a certificate from the old root":                      {stolen},
		"a certificate from a new admin CA under the old root": {viaThiefCA, thiefCA.Cert},
	} {
		if s.Refused(chain) == nil {
			t.Errorf("%s is not refused", name)
		}
	}
}

func TestRootRecordsOrderIndependent(t *testing.T) {
	h := newHandover(t)
	var want string
	for i := range 20 {
		rng := rand.New(rand.NewPCG(uint64(i), 2))
		rs := make([]Record, len(h.all))
		for j, k := range rng.Perm(len(h.all)) {
			rs[j] = h.all[k]
		}
		s := NewRecords(h.pg.root.Cert)
		if _, errs := s.AddAll(rs); len(errs) > 0 {
			t.Fatal(errs)
		}
		s.SetClock(afterDelay)
		got, _ := json.Marshal(s.Devices())
		got = append(got, s.Digest()...)
		got = append(got, s.Roots()[0].Raw...)
		if i == 0 {
			want = string(got)
		} else if string(got) != want {
			t.Fatalf("order %d differs", i)
		}
	}
	// Without its claim, a record signed by the new root is not valid.
	if _, err := NewRecords(h.pg.root.Cert).Add(h.all[len(h.all)-1]); err == nil {
		t.Error("accepted a record from an unknown root")
	}
}

// TestRootTieBreak checks that two claims under the same root never choose
// between them: the group stops fully until the root decides, and neither
// new root counts.
func TestRootTieBreak(t *testing.T) {
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	x, y := newRoot(t), newRoot(t)
	s := NewRecords(g)
	mustAdd(t, s, adminRecord(t, g, pg.root, nil, member(t, pg.a), "phone A", KeyHashOf(pg.a.Cert)))
	mustAdd(t, s, adminRecord(t, g, pg.root, nil, member(t, pg.b), "phone B", KeyHashOf(pg.b.Cert)))
	mustAdd(t, s, claimRecord(t, g, pg.a, []*x509.Certificate{pg.a.Cert}, x.Cert))
	// B signs its claim without having seen A's.
	r, err := signRecord(RecordBody{Type: RecordClaim, Group: Tag(g), TimeMS: nextTime(), Root: y.Cert.Raw,
		Seen: []authority.Seen{{Key: KeyHashOf(g), Seq: 2}}}, pg.b.Key, pg.b.Cert)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, s, r)
	s.SetClock(afterDelay)
	if len(s.Roots()) != 0 || s.Stop() != "full" {
		t.Errorf("two claims: roots %d, stop %q", len(s.Roots()), s.Stop())
	}
	// The root removes both claimants: the group goes on under the root.
	mustAdd(t, s, revokeRecord(t, g, pg.root, nil, []KeyHash{KeyHashOf(pg.a.Cert), KeyHashOf(pg.b.Cert)}))
	if len(s.Roots()) != 0 || s.Stop() != "none" {
		t.Errorf("after the root's removal: roots %d, stop %q", len(s.Roots()), s.Stop())
	}
}

func TestRootRecordsRejected(t *testing.T) {
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	for name, root := range map[string]*x509.Certificate{
		"an admin CA": pg.a.Cert,
		"a member":    member(t, pg.root),
	} {
		s := NewRecords(g)
		mustAdd(t, s, adminRecord(t, g, pg.root, nil, member(t, pg.a), "phone a", KeyHashOf(pg.a.Cert)))
		r, err := signRecord(RecordBody{Type: RecordClaim, Group: Tag(g), TimeMS: nextTime(), Root: root.Raw}, pg.a.Key, pg.a.Cert)
		if err != nil {
			continue
		}
		s.AddAll([]Record{r})
		s.SetClock(afterDelay)
		if len(s.Roots()) != 0 {
			t.Errorf("a claim with %s as the new root took effect", name)
		}
	}
}

// TestIdentityWithRoots checks a computer's identity after the handover: it
// keeps its certificate from the old root, takes a renewal from the new
// one, and talks to a member the new root admitted.
func TestIdentityWithRoots(t *testing.T) {
	h := newHandover(t)
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewDeviceID()
	cert, err := h.pg.root.IssueMember(dev, &key.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{ID: dev, Key: key, Cert: cert, GroupCA: CA{Cert: h.pg.root.Cert}, Roots: []*x509.Certificate{h.newRoot.Cert}}
	dir := t.TempDir()
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	back, err := Load(dir)
	if err != nil || len(back.Roots) != 1 || !back.Root().Equal(h.newRoot.Cert) {
		t.Fatalf("loaded %v, error %v", back, err)
	}
	renewed, err := h.newRoot.IssueMember(dev, &key.PublicKey, t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	next, err := id.WithCert(renewed.Raw)
	if err != nil {
		t.Fatalf("a renewal from the new root: %v", err)
	}
	if _, err := (&Identity{ID: dev, Key: key, Cert: cert, GroupCA: CA{Cert: h.pg.root.Cert}}).WithCert(renewed.Raw); err == nil {
		t.Error("an identity that does not know the new root took its certificate")
	}

	peerKey, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	peerDev := NewDeviceID()
	peerCert, err := h.newRoot.IssueMember(peerDev, &peerKey.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	peer := &Identity{ID: peerDev, Key: peerKey, Cert: peerCert, GroupCA: CA{Cert: h.pg.root.Cert}, Roots: []*x509.Certificate{h.newRoot.Cert}}
	at := TLSOptions{Now: func() time.Time { return t0.Add(48 * time.Hour) }}
	for _, p := range [][2]*Identity{{id, peer}, {peer, next}} {
		if _, _, cerr, serr := handshake(t, p[0].ClientTLS(p[1].ID, at), p[1].ServerTLS(at)); cerr != nil || serr != nil {
			t.Fatalf("handshake: client %v, server %v", cerr, serr)
		}
	}
	bad := *id
	bad.Roots = []*x509.Certificate{h.pg.a.Cert}
	if bad.Check() == nil {
		t.Error("accepted an admin CA as a later root")
	}
}

// TestUpgradeRecords checks that the records of a group that a legacy
// group CA handed to a root (cbb upgrade, version 1) are refused: there is
// no migration to version 2.
func TestUpgradeRecords(t *testing.T) {
	checkV1Refused(t)
}

// TestOldGroup checks that an identity of a group made before 0.4, whose
// group CA certifies no admin CAs, is refused with ErrOldGroup.
func TestOldGroup(t *testing.T) {
	id := newGroup(t)
	ca, err := NewGroupCA(t0)
	if err != nil {
		t.Fatal(err)
	}
	id.GroupCA, id.PhoneCA, id.Phone = *ca, nil, nil
	if id.Cert, err = ca.IssueMember(id.ID, PublicKey(id.Key), t0); err != nil {
		t.Fatal(err)
	}
	if err := id.Check(); !errors.Is(err, ErrOldGroup) {
		t.Errorf("Check of a group made before 0.4: %v, want ErrOldGroup", err)
	}
}

// TestPathRecords checks that the records a Welcome carries lead a new
// device to the same roots as the whole set.
func TestPathRecords(t *testing.T) {
	h := newHandover(t)
	s := h.records(t)
	path := s.PathRecords()
	fresh := NewRecords(h.pg.root.Cert)
	if _, errs := fresh.AddAll(path); len(errs) > 0 {
		t.Fatal(errs)
	}
	clear(fresh.firstSeen)
	for k, v := range s.firstSeen {
		fresh.firstSeen[k] = v
	}
	fresh.SetClock(afterDelay)
	if roots := fresh.Roots(); len(roots) != 1 || !roots[0].Equal(h.newRoot.Cert) {
		t.Fatalf("the path records lead to %d roots, want the new root", len(roots))
	}
	if got := NewRecords(h.pg.root.Cert).PathRecords(); len(got) != 0 {
		t.Errorf("%d path records in an empty set", len(got))
	}
}

// TestFullSetTakesTheRoot checks that admins that fill the set to
// MaxRecords leave room for the root's own records, so the root still
// removes them, and that no one admin goes past MaxPerSigner.
func TestFullSetTakesTheRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("signs MaxRecords records")
	}
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	admins := []*CA{pg.a, pg.b, adminCA(t, pg.root), adminCA(t, pg.root)}
	s := NewRecords(g)
	for _, a := range admins {
		mustAdd(t, s, computerAdminRecord(t, pg, member(t, a), "pc", KeyHashOf(a.Cert)))
	}
	laptop := member(t, pg.a)
	var err error
	for i := 0; err == nil; i++ {
		a := admins[i/MaxPerSigner%len(admins)]
		_, err = s.Add(deviceRecord(t, g, a, []*x509.Certificate{a.Cert}, laptop, "laptop", int64(i+1)))
	}
	if s.Len() != MaxRecords {
		t.Fatalf("the set stopped at %d records, want %d: %v", s.Len(), MaxRecords, err)
	}
	if _, err := s.Add(deviceRecord(t, g, pg.a, []*x509.Certificate{pg.a.Cert}, laptop, "laptop", 1<<40)); err == nil {
		t.Error("an admin went past MaxPerSigner")
	}
	var keys []KeyHash
	for _, a := range admins {
		keys = append(keys, KeyHashOf(a.Cert))
	}
	mustAdd(t, s, revokeRecord(t, g, pg.root, nil, keys))
	for _, k := range keys {
		if !s.Revoked(k) {
			t.Error("the full set did not take the root's removal of an admin")
		}
	}
}
