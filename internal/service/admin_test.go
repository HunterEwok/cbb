// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/attest/attesttest"
	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/release"
)

// fakePhone is the root phone of a group, which dials a computer and sends
// it member protocol messages as the app does.
type fakePhone struct {
	t  *testing.T
	id *group.Identity
	tc *tls.Conn
}

func (p *fakePhone) dial(h *hub, to *group.Identity) {
	p.t.Helper()
	addr := ""
	h.mu.Lock()
	for m := range h.members {
		if m.cfg.ID == string(to.ID) {
			addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(m.cfg.Port)))
		}
	}
	h.mu.Unlock()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { raw.Close() })
	p.tc = tls.Client(raw, p.id.ClientTLS(to.ID, group.TLSOptions{}))
	if err := p.tc.Handshake(); err != nil {
		p.t.Fatal(err)
	}
	p.send(map[string]any{"t": "hello", "role": "phone", "hello": map[string]any{"wall_ms": time.Now().UnixMilli()}})
}

func (p *fakePhone) send(m map[string]any) {
	p.t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.tc.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(data))), data...)); err != nil {
		p.t.Fatal(err)
	}
}

// adminCAFor issues the admin CA of the computer id under root.
func adminCAFor(t *testing.T, root *group.CA, id *group.Identity) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: group.AdminName(id.ID)},
		NotBefore:             root.Cert.NotBefore,
		NotAfter:              root.Cert.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, group.PublicKey(id.AdminKey), root.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestComputerAdmin checks a computer of a phone group that the root phone
// makes an admin: it offers its admin key, takes the admin CA from the
// phone, then admits a computer and removes it, which the other members
// follow, and refuses to remove the root phone.
func TestComputerAdmin(t *testing.T) {
	root := testCA(t, nil)
	piDir, pi := memberIn(t, root, root)
	deckDir, deck := memberIn(t, root, root)
	_, phone := memberIn(t, root, root)

	g := root.Cert
	pk, dk, phk := group.KeyHashOf(pi.Cert), group.KeyHashOf(deck.Cert), group.KeyHashOf(phone.Cert)
	recs := group.NewRecords(g)
	if _, errs := recs.AddAll([]group.Record{
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: string(phone.ID), Name: "iphone", Role: group.RolePhone, Key: &phk, HoldsRoot: true}, root.Key),
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: string(pi.ID), Name: "pi", Role: group.RoleMember, Caps: group.AllCaps, Key: &pk}, root.Key),
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: string(deck.ID), Name: "deck", Role: group.RoleMember, Caps: group.AllCaps, Key: &dk}, root.Key),
	}); len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, dir := range []string{piDir, deckDir} {
		if err := recs.Save(dir); err != nil {
			t.Fatal(err)
		}
	}

	var h hub
	a := startIn(t, &h, &testService{name: "pi", dir: piDir, os: group.OSLinux})
	b := startIn(t, &h, &testService{name: "deck", dir: deckDir, os: group.OSLinux})
	waitFor(t, "pi and deck connected", func() bool { return len(a.status(t).Peers) == 1 })
	if _, err := a.do(t, control.Header{Op: control.OpRevoke, Name: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("revoke before the pi is an admin: %v", err)
	}
	pending, err := group.Load(piDir)
	if err != nil || pending.AdminKey == nil || pending.AdminCA != nil {
		t.Fatalf("the pi has no admin key: %v", err)
	}

	// The root phone makes the pi an admin, and lists it as one.
	ca := adminCAFor(t, root, pending)
	ak := group.KeyHashOf(ca)
	p := &fakePhone{t: t, id: phone}
	p.dial(&h, pi)
	p.send(map[string]any{"t": "admin", "admin_ca": ca.Raw})
	p.send(map[string]any{"t": "records", "records": []group.Record{
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: string(pi.ID), Name: "pi", Role: group.RoleMember, Caps: group.AllCaps, Key: &pk, Admin: &ak,
			Powers: []string{authority.PowerAdmit, authority.PowerFreeze, authority.PowerHub, authority.PowerRemove, authority.PowerRenew}, Commands: authority.Commands}, root.Key),
	}})
	waitFor(t, "the pi keeps its admin CA", func() bool {
		id, err := group.Load(piDir)
		return err == nil && id.AdminCA != nil && id.AdminCA.Equal(ca)
	})
	for _, s := range []*testService{a, b} {
		waitFor(t, s.name+" lists the pi as an admin", func() bool {
			for _, d := range s.devices(t) {
				if d.Name == "pi" {
					return d.Admin
				}
			}
			return false
		})
	}

	if _, err := a.do(t, control.Header{Op: control.OpRevoke, Name: "iphone"}, ""); err == nil || !strings.Contains(err.Error(), "group's root") {
		t.Errorf("revoking the root phone: %v", err)
	}
	// The pi admits a computer from its admin CA, which every member
	// lists, and removes it again.
	c := startService(t, &h, "laptop")
	pairWith(t, a, c)
	joined, err := group.Load(c.dir)
	if err != nil || joined.Issuer == nil || !joined.Issuer.Equal(ca) || joined.AdminKey == nil {
		t.Fatalf("the new computer's identity: %v", err)
	}
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" lists the laptop", func() bool { return listed(s.devices(t)) == "deck iphone laptop pi" })
		waitFor(t, s.name+" connected", func() bool { return len(s.status(t).Peers) >= 2 })
	}
	if _, err := a.do(t, control.Header{Op: control.OpRevoke, Name: "laptop"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck drops the laptop", func() bool { return listed(b.devices(t)) == "deck iphone pi" })
	waitFor(t, "the laptop is cut off", func() bool { return len(c.status(t).Peers) == 0 })
}

// TestAdminPeerNeedsARealAdminCA checks that a member counts as an admin
// through its chain only with an admin CA that issued its certificate and
// that a root of the group certified, not with any CA named after it.
func TestAdminPeerNeedsARealAdminCA(t *testing.T) {
	now := time.Now()
	root, err := group.Create(now)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{id: root, records: group.NewRecords(root.GroupCA.Cert)}
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := group.NewDeviceID()
	leaf, err := root.GroupCA.IssueMember(dev, &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	// A CA the member made itself, named as its admin CA would be.
	own, err := group.NewGroupCA(now)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: group.AdminName(dev)},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, group.PublicKey(own.Key), own.Key)
	if err != nil {
		t.Fatal(err)
	}
	fake, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if s.adminPeer(dev, []*x509.Certificate{leaf, fake}) {
		t.Error("a member counted as an admin with a CA it made itself")
	}
	// The real thing: an admin CA from the root, which issued the leaf.
	adminKey, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	adminCA, err := root.GroupCA.IssueAdmin(dev, &adminKey.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := (&group.CA{Cert: adminCA, Key: adminKey}).IssueMember(dev, &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.adminPeer(dev, []*x509.Certificate{issued, adminCA}) {
		t.Error("a member with its admin CA did not count as an admin")
	}
}

// The root makes a computer whose keys sit in a file an admin only when
// the user allows it, and its record says where its keys live.
func TestAdminOfFileKeys(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "deck is connected to the root", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := pi.do(t, control.Header{Op: control.OpAdmin, Name: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "-allow-file-key") {
		t.Fatalf("admin without consent: %v", err)
	}
	makeAdmin(t, pi, deck)
	for _, d := range pi.devices(t) {
		if d.Name == "deck" && (!d.Admin || d.Store != group.StoreFile) {
			t.Errorf("deck after admin: %+v", d)
		}
	}
}

// A group whose root keeps its key in a file starts at the key level
// files; only its root sets the level, never above its own key, and a new
// takeover delay keeps the level.
func TestKeyLevelSetting(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "deck is connected to the root", func() bool { return len(pi.status(t).Peers) == 1 })
	if l := pi.status(t).KeyLevel; l != LevelFiles {
		t.Fatalf("the level of a group with a root key in a file: %q", l)
	}
	waitFor(t, "deck has the level", func() bool { return deck.status(t).KeyLevel == LevelFiles })
	if _, err := deck.do(t, control.Header{Op: control.OpKeyLevel, Value: LevelFiles}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("the level set on a member: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpKeyLevel, Value: "any"}, ""); err == nil || !strings.Contains(err.Error(), "proven, hardware or files") {
		t.Errorf("an unknown level: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpKeyLevel, Value: LevelHardware}, ""); err == nil || !strings.Contains(err.Error(), "the group's root, keeps its keys in a file") {
		t.Errorf("a level above the root's own key: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpDelay, Value: "24h"}, ""); err != nil {
		t.Fatal(err)
	}
	if l := pi.status(t).KeyLevel; l != LevelFiles {
		t.Errorf("the level after a new takeover delay: %q", l)
	}
}

// levelAllows lets in what each level allows, and a key in a file only with
// the user's consent.
func TestLevelAllows(t *testing.T) {
	for _, c := range []struct {
		level, store string
		consent      bool
		want         string
	}{
		{LevelFiles, group.StoreRootless, true, "without root"},
		{LevelProven, group.StoreHardware, true, "attestation does not prove"},
		{LevelProven, group.StoreProven, false, ""},
		{LevelHardware, group.StoreHardware, false, ""},
		{LevelHardware, group.StoreFile, true, "cbb keys files"},
		{LevelFiles, group.StoreFile, false, "allow it anyway, HINT"},
		{LevelFiles, group.StoreFile, true, ""},
		{LevelFiles, group.StoreHardware, false, ""},
	} {
		err := levelAllows(c.level, c.store, "desk", "HINT", c.consent)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s, %s, consent %v: %v", c.level, c.store, c.consent, err)
		}
	}
}

// The root renames any device with a newer device record, which every
// member takes; the device keeps its role and whether it is an admin. An
// admin renames the devices that are no admin, phone or watch, and not the
// root's own.
func TestRename(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, deck)
	pairWith(t, pi, mac)
	waitFor(t, "the Mac lists every device", func() bool { return listed(mac.devices(t)) == "deck mac pi" })
	makeAdmin(t, pi, deck)
	if _, err := mac.do(t, control.Header{Op: control.OpRename, Name: "deck", NewName: "steam deck"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("rename on the Mac: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRename, Name: "deck", NewName: " "}, ""); err == nil || !strings.Contains(err.Error(), "1 to 64") {
		t.Errorf("an empty name: %v", err)
	}
	m, err := pi.do(t, control.Header{Op: control.OpRename, Name: "deck", NewName: "steam deck"}, "")
	if err != nil || m.Name != "deck" {
		t.Fatalf("rename: %+v %v", m, err)
	}
	// Only the root renames itself or an admin (docs/protocol.md, section 10, "Who
	// signs what").
	if _, err := deck.do(t, control.Header{Op: control.OpRename, Name: "pi", NewName: "pi4"}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("the admin renamed the root: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRename, Name: "pi", NewName: "pi4"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{pi, deck, mac} {
		waitFor(t, s.name+" takes the new names", func() bool { return listed(s.devices(t)) == "mac pi4 steam deck" })
	}
	for _, d := range mac.devices(t) {
		if d.Name == "steam deck" && (!d.Admin || d.Role != group.RoleMember) || d.Name == "pi4" && !d.Root {
			t.Errorf("after the rename: %+v", d)
		}
	}
}

// TestEvidence checks that the group's root records what a device's
// attestation proves: proven for a valid chain of its member key, nothing
// for a chain of another key.
func TestEvidence(t *testing.T) {
	// The revocation list's mirror: keys.json from a root key, and a list
	// the test changes.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	statusKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSPKI, _ := x509.MarshalPKIXPublicKey(&rootKey.PublicKey)
	statusSPKI, _ := x509.MarshalPKIXPublicKey(&statusKey.PublicKey)
	now := time.Now().UnixMilli()
	keysFile, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: 1, TimeMS: now, ExpiresMS: now + 3600_000,
		Keys: []release.Key{{Key: statusSPKI, Name: "status", Use: release.UseStatus}}}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	var listMu sync.Mutex
	list := release.Status{V: 1, Type: release.TypeStatus, Seq: 1, TimeMS: now, ExpiresMS: now + 3600_000, AndroidRevoked: []string{}}
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listMu.Lock()
		defer listMu.Unlock()
		f := keysFile
		if r.URL.Path == "/attest-status.json" {
			var err error
			if f, err = release.Sign(list, statusKey); err != nil {
				t.Error(err)
			}
		}
		json.NewEncoder(w).Encode(f)
	}))
	defer mirror.Close()
	oldURL, oldRoots, oldEvery := statusURL, statusRoots, statusEvery
	statusURL, statusRoots, statusEvery = mirror.URL+"/", func() [][]byte { return [][]byte{rootSPKI} }, 100*time.Millisecond
	t.Cleanup(func() { statusURL, statusRoots, statusEvery = oldURL, oldRoots, oldEvery })

	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "deck is listed", func() bool { return listed(pi.devices(t)) == "deck pi" })
	deck.stop()
	id, err := group.Load(deck.dir)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 16)
	challenge, _ := attest.Challenge("", nil, salt)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong, wrongRoot, err := attesttest.Android(&other.PublicKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	chain, root, err := attesttest.Android(id.Cert.PublicKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	attestRoots = [][]byte{wrongRoot, root}
	t.Cleanup(func() { attestRoots = nil })

	p := &fakePhone{t: t, id: id}
	p.dial(&h, mustLoad(t, pi.dir))
	ev := func(chain [][]byte) map[string]any {
		return map[string]any{"t": "evidence", "evidence": map[string]any{"format": "android-key", "key": "member", "salt": salt, "chain": chain}}
	}
	p.send(ev(wrong))
	p.send(ev(chain))
	store := func() string {
		for _, d := range pi.devices(t) {
			if d.Name == "deck" {
				return d.Store
			}
		}
		return ""
	}
	waitFor(t, "the root records the deck's keys as proven", func() bool { return store() == group.StoreProven })

	// Google revokes the chain's attestation key: the root takes the new
	// list and records the deck's keys as only in hardware.
	ca, err := x509.ParseCertificate(chain[1])
	if err != nil {
		t.Fatal(err)
	}
	listMu.Lock()
	list.Seq, list.AndroidRevoked = 2, []string{ca.SerialNumber.Text(16)}
	listMu.Unlock()
	waitFor(t, "the root records the deck's keys as in hardware", func() bool { return store() == group.StoreHardware })
}

func mustLoad(t *testing.T, dir string) *group.Identity {
	t.Helper()
	id, err := group.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestHubsTable: the root signs the group's main hubs, which come first in
// every member's order of hubs; an admin without a hub set up, a device
// that cannot be a hub and a device named twice are refused.
func TestHubsTable(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, deck)
	pairWith(t, pi, mac)
	waitFor(t, "the Mac lists every device", func() bool { return listed(mac.devices(t)) == "deck mac pi" })
	makeAdmin(t, pi, deck)
	if _, err := mac.do(t, control.Header{Op: control.OpHubs, Hubs: []string{"pi"}}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("hubs on the Mac: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpHubs, Hubs: []string{"deck", "deck"}}, ""); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a hub named twice: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpHubs}, ""); err == nil || !strings.Contains(err.Error(), "1 to 16") {
		t.Errorf("no hubs: %v", err)
	}
	var deckID string
	for _, d := range mac.devices(t) {
		if d.Name == "deck" {
			deckID = d.ID
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpHubs, Hubs: []string{deckID, "pi"}}, ""); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{pi, deck, mac} {
		waitFor(t, s.name+" puts the deck first", func() bool {
			order := hubOrderIn(s.dir)
			return len(order) == 2 && string(order[0]) == deckID
		})
	}
}

// hubOrderIn returns the order of hubs of the records in dir.
func hubOrderIn(dir string) []group.DeviceID {
	id, err := group.Load(dir)
	if err != nil {
		return nil
	}
	recs, err := group.LoadRecords(dir, id.GroupCA.Cert)
	if err != nil {
		return nil
	}
	return recs.HubOrder()
}
