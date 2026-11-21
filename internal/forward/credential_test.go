// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

// TestCredentialRegistration checks a hub that registers with its period's
// hubs' credential (docs/protocol.md, section 13): its certificate names
// neither a device nor a group; the forwarder takes only a hub the
// credential lists, refuses an expired or older credential, and, once it
// saw a period key for a tag, any other key for it, also after a restart;
// and its state names neither the period's tag nor its key.
func TestCredentialRegistration(t *testing.T) {
	now := time.Now()
	state := filepath.Join(t.TempDir(), "state.json")
	fcert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, pin := startForwarderWith(t, Config{Cert: fcert, StateFile: state})
	g := newTestGroup(t)
	hub := g.cert
	if strings.Contains(string(hub.Leaf.Raw), "cb-") || hub.Leaf.Subject.CommonName != group.ServerCertificateName {
		t.Fatalf("the hub's certificate names a device: %v", hub.Leaf.Subject)
	}
	rogueKey, rogueCert := newServerKey(t)
	sign := func(by *ecdsa.PrivateKey, v uint64, expires time.Time) hubAuth {
		return hubAuth{creds: [][]byte{g.signHubs(t, by, v, expires)}}
	}
	live := now.Add(periodLifetime)
	wg, _ := ecdh.X25519().GenerateKey(rand.Reader)
	register := func(f *Forwarder, pin string, cert tls.Certificate, auth hubAuth) answer {
		t.Helper()
		return rawRegister(t, f, pin, cert, wg.PublicKey().Bytes(), wg, auth)
	}

	if a := register(f, pin, hub, sign(g.period, 10, live)); a.Error != "" || a.ID == 0 {
		t.Fatalf("the hub with its credential: %+v", a)
	}
	if a := register(f, pin, rogueCert, sign(g.period, 10, live)); !strings.Contains(a.Error, "does not list") {
		t.Errorf("a key the credential does not list: %+v", a)
	}
	if a := register(f, pin, hub, sign(g.period, 11, now.Add(-time.Hour))); !strings.Contains(a.Error, "expired") {
		t.Errorf("an expired credential: %+v", a)
	}
	if a := register(f, pin, hub, sign(g.period, 9, live)); !strings.Contains(a.Error, "older") {
		t.Errorf("an older credential: %+v", a)
	}
	if a := register(f, pin, hub, sign(rogueKey, 12, live)); !strings.Contains(a.Error, "first") {
		t.Errorf("a credential another key signed for the tag: %+v", a)
	}
	if a := register(f, pin, hub, hubAuth{creds: [][]byte{g.hubs(t, 12), g.periodCredential(t)}}); !strings.Contains(a.Error, "alone") {
		t.Errorf("a period sent to the forwarder: %+v", a)
	}
	other, _ := NewCert()
	withCA := tls.Certificate{Certificate: [][]byte{hub.Certificate[0], other.Certificate[0]}, PrivateKey: g.hub, Leaf: hub.Leaf}
	if a := register(f, pin, withCA, sign(g.period, 13, live)); a.Error == "" {
		t.Errorf("a server certificate with another behind it: %+v", a)
	}

	// After a restart on the same state the older credential and the other
	// key stay refused. The forwarder writes its state when it stops.
	f.Close()
	h, hpin := startForwarderWith(t, Config{Cert: fcert, StateFile: state})
	if a := register(h, hpin, hub, sign(g.period, 9, live)); !strings.Contains(a.Error, "older") {
		t.Errorf("an older credential after a restart: %+v", a)
	}
	if a := register(h, hpin, hub, sign(rogueKey, 20, live)); !strings.Contains(a.Error, "first") {
		t.Errorf("another key after a restart: %+v", a)
	}
	if a := register(h, hpin, hub, sign(g.period, 20, live)); a.Error != "" {
		t.Errorf("a newer credential after a restart: %+v", a)
	}

	// The state names neither the period's tag nor its key.
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	pk := serverKeyHash(g.period)
	for _, c := range []string{hex.EncodeToString(g.tag[:]), hex.EncodeToString(pk[:])} {
		if strings.Contains(string(b), c) {
			t.Errorf("the state file holds %q: %s", c, b)
		}
	}
}

// TestRemoveGroupFiles checks that the files earlier versions kept for each
// group are deleted, and nothing else.
func TestRemoveGroupFiles(t *testing.T) {
	dir := t.TempDir()
	groups := filepath.Join(dir, "groups")
	os.Mkdir(groups, 0o700)
	for _, name := range []string{"0123456789abcdef.json", "fedcba9876543210.json.tmp"} {
		os.WriteFile(filepath.Join(groups, name), []byte("[]"), 0o600)
	}
	if n, err := RemoveGroupFiles(groups); n != 2 || err != nil {
		t.Errorf("removed %d: %v", n, err)
	}
	if _, err := os.Stat(groups); !os.IsNotExist(err) {
		t.Errorf("the empty directory stayed: %v", err)
	}
	os.Mkdir(groups, 0o700)
	os.WriteFile(filepath.Join(groups, "notes.txt"), nil, 0o600)
	if n, err := RemoveGroupFiles(groups); n != 0 || err != nil {
		t.Errorf("removed %d: %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(groups, "notes.txt")); err != nil {
		t.Errorf("another file went: %v", err)
	}
}
