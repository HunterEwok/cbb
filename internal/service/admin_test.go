// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/attest/attesttest"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/release"
)

// TestComputerAdmin checks a computer that the group's root makes an
// admin: it offered its admin key when it paired with the root, then admits
// a computer and removes it, which the other members follow, and refuses to
// remove the root. On the records of 0.6 the root here is a computer; a
// root phone's side is the phones' (the TestFFI tests).
func TestComputerAdmin(t *testing.T) {
	var h hub
	root := startService(t, &h, "root")
	a := startService(t, &h, "pi")
	b := startService(t, &h, "deck")
	pairWith(t, root, a)
	pairWith(t, root, b)
	waitFor(t, "pi and deck connected", func() bool { return len(a.status(t).Peers) == 2 })
	if _, err := a.do(t, control.Header{Op: control.OpRemove, Device: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("revoke before the pi is an admin: %v", err)
	}
	// It offered its admin key as it paired: keys.json (src/own.rs in
	// cbb) keeps one beside its member key.
	var keys struct {
		Admin json.RawMessage `json:"admin"`
	}
	if raw, err := os.ReadFile(filepath.Join(a.dir, "keys.json")); err != nil || json.Unmarshal(raw, &keys) != nil || len(keys.Admin) == 0 {
		t.Fatalf("the pi has no admin key: %v", err)
	}

	// The root makes the pi an admin, and every member lists it as one.
	makeAdmin(t, root, a)
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

	if _, err := a.do(t, control.Header{Op: control.OpRemove, Device: "root"}, ""); err == nil || !strings.Contains(err.Error(), "group's root") {
		t.Errorf("revoking the root: %v", err)
	}
	// The pi admits a computer, which every member lists, and removes it
	// again.
	c := startService(t, &h, "laptop")
	pairWith(t, a, c)
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" lists the laptop", func() bool { return listed(s.devices(t)) == "deck laptop pi root" })
		waitFor(t, s.name+" connected", func() bool { return len(s.status(t).Peers) >= 2 })
	}
	if _, err := a.do(t, control.Header{Op: control.OpRemove, Device: "laptop"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck drops the laptop", func() bool { return listed(b.devices(t)) == "deck pi root" })
	waitFor(t, "the laptop is cut off", func() bool { return len(c.status(t).Peers) == 0 })
}

// The root makes a computer whose keys sit in a file an admin only when
// the user allows it, and its record says where its keys live.
func TestAdminOfFileKeys(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "deck is connected to the root", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Device: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "-allow-file-key") {
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
	if l := pi.status(t).KeyLevel; l != "files" {
		t.Fatalf("the level of a group with a root key in a file: %q", l)
	}
	waitFor(t, "deck has the level", func() bool { return deck.status(t).KeyLevel == "files" })
	if _, err := deck.do(t, control.Header{Op: control.OpKeyLevel, Value: "files"}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("the level set on a member: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpKeyLevel, Value: "any"}, ""); err == nil || !strings.Contains(err.Error(), "proven, hardware or files") {
		t.Errorf("an unknown level: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpKeyLevel, Value: "hardware"}, ""); err == nil || !strings.Contains(err.Error(), "the group's root, keeps its keys in a file") {
		t.Errorf("a level above the root's own key: %v", err)
	}
	// On the records of 0.6 a claim has no delay to set (cbb recovery
	// changes the root); another setting the root signs keeps the level.
	if _, err := pi.do(t, control.Header{Op: control.OpDelay, Value: "24h"}, ""); err == nil || !strings.Contains(err.Error(), "cbb recovery") {
		t.Errorf("a takeover delay on the records of 0.6: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpIncoming, Value: "2m"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "deck takes the new setting", func() bool { return deck.status(t).IncomingMS == 120_000 })
	for _, s := range []*testService{pi, deck} {
		if l := s.status(t).KeyLevel; l != "files" {
			t.Errorf("the level on %s after a new setting: %q", s.name, l)
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
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, deck)
	pairWith(t, pi, laptop)
	waitFor(t, "the laptop lists every device", func() bool { return listed(laptop.devices(t)) == "deck laptop pi" })
	makeAdmin(t, pi, deck)
	if _, err := laptop.do(t, control.Header{Op: control.OpRename, Device: "deck", Name: "steam deck"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("rename on the laptop: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRename, Device: "deck", Name: " "}, ""); err == nil || !strings.Contains(err.Error(), "1 to 64") {
		t.Errorf("an empty name: %v", err)
	}
	m, err := pi.do(t, control.Header{Op: control.OpRename, Device: "deck", Name: "steam deck"}, "")
	if err != nil || m.Name != "deck" {
		t.Fatalf("rename: %+v %v", m, err)
	}
	// Only the root renames itself or an admin (docs/protocol.md, section 10, "Who
	// signs what").
	if _, err := deck.do(t, control.Header{Op: control.OpRename, Device: "pi", Name: "pi4"}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("the admin renamed the root: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRename, Device: "pi", Name: "pi4"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{pi, deck, laptop} {
		waitFor(t, s.name+" takes the new names", func() bool { return listed(s.devices(t)) == "laptop pi4 steam deck" })
	}
	for _, d := range laptop.devices(t) {
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
	rootKey, _ := release.GenerateSigner()
	statusKey, _ := release.GenerateSigner()
	statusKeys, _ := statusKey.Keys("status", release.UseStatus)
	now := time.Now().UnixMilli()
	keysFile, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: 1, TimeMS: now, ExpiresMS: now + 3600_000,
		Keys: statusKeys}, rootKey)
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
	dir := t.TempDir()
	statusRoots := dir + "/release-roots.pem"
	rootsPEM, _ := release.PublicPEM(rootKey, "root-1")
	if err := os.WriteFile(statusRoots, rootsPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// The attestation roots the root's cbb-helper reads at each check.
	attestRoots := dir + "/attest-roots.pem"

	var h hub
	pi := startEnv(t, &h, "pi", "CBB_TEST_ATTEST_ROOTS="+attestRoots, "CBB_TEST_STATUS_URL="+mirror.URL+"/",
		"CBB_TEST_STATUS_EVERY=100", "CBB_RELEASE_ROOTS="+statusRoots)
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "deck is listed", func() bool { return listed(pi.devices(t)) == "deck pi" })
	deck.stop()
	member := memberKey06(t, deck.dir)
	salt := make([]byte, 16)
	challenge, _ := attest.Challenge("", nil, salt)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong, wrongRoot, err := attesttest.Android(&other.PublicKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	chain, root, err := attesttest.Android(member, challenge)
	if err != nil {
		t.Fatal(err)
	}
	var roots []byte
	for _, r := range [][]byte{wrongRoot, root} {
		roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: r})...)
	}
	if err := os.WriteFile(attestRoots, roots, 0o644); err != nil {
		t.Fatal(err)
	}

	// The deck sends the two chains as a phone sends its own, the one of
	// another key first (CBB_TEST_OWN_EVIDENCE, a build for tests).
	ev := func(chain [][]byte) map[string]any {
		return map[string]any{"format": "android-key", "key": "member", "salt": salt, "chain": chain}
	}
	evidence, err := json.Marshal([]map[string]any{ev(wrong), ev(chain)})
	if err != nil {
		t.Fatal(err)
	}
	evidenceFile := dir + "/evidence.json"
	if err := os.WriteFile(evidenceFile, evidence, 0o600); err != nil {
		t.Fatal(err)
	}
	deck.env = append(deck.env, "CBB_TEST_OWN_EVIDENCE="+evidenceFile)
	restartService(t, &h, deck)
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

// memberKey06 is the public member key of the device of 0.6 whose state
// is in dir, from its keys.json (member/src/own.rs).
func memberKey06(t *testing.T, dir string) *ecdsa.PublicKey {
	t.Helper()
	var f struct {
		Member struct {
			PKCS8 []byte `json:"pkcs8"`
		} `json:"member"`
	}
	raw, err := os.ReadFile(dir + "/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(f.Member.PKCS8)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("the member key is a %T", k)
	}
	return &ec.PublicKey
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
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, deck)
	pairWith(t, pi, laptop)
	waitFor(t, "the laptop lists every device", func() bool { return listed(laptop.devices(t)) == "deck laptop pi" })
	makeAdmin(t, pi, deck)
	if _, err := laptop.do(t, control.Header{Op: control.OpHubs, Hubs: []string{"pi"}}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("hubs on the laptop: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpHubs, Hubs: []string{"deck", "deck"}}, ""); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a hub named twice: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpHubs}, ""); err == nil || !strings.Contains(err.Error(), "1 to 16") {
		t.Errorf("no hubs: %v", err)
	}
	var deckID string
	for _, d := range laptop.devices(t) {
		if d.Name == "deck" {
			deckID = d.ID
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpHubs, Hubs: []string{deckID, "pi"}}, ""); err != nil {
		t.Fatal(err)
	}
	// Every member derives the same order from the records: the deck,
	// then the pi; the laptop, neither named nor an admin, serves not.
	for _, s := range []*testService{pi, deck, laptop} {
		waitFor(t, s.name+" puts the deck first", func() bool {
			return hubOrderOf(t, s) == "deck pi"
		})
	}
}

// hubOrderOf returns the names of the devices s lists in the group's order
// of hubs, space-separated.
func hubOrderOf(t *testing.T, s *testService) string {
	t.Helper()
	var order []string
	for _, d := range s.devices(t) {
		if d.HubRank == 0 {
			continue
		}
		for len(order) < d.HubRank {
			order = append(order, "")
		}
		order[d.HubRank-1] = d.Name
	}
	return strings.Join(order, " ")
}

// TestRelayOnTheRootAlone: on the records of 0.6 only the group's root sets
// the group's relay; an admin is told to run it there.
func TestRelayOnTheRootAlone(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	makeAdmin(t, pi, deck)
	_, err := deck.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: "default", Consent: true}, "")
	if err == nil || !strings.Contains(err.Error(), "only the group's root sets the group's relay") {
		t.Errorf("cbb global relay on an admin: %v", err)
	}
}
