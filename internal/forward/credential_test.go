// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

// TestCredentialRegistration checks a hub that registers with its period's
// hubs' credential (docs/protocol.md, section 18): its certificate names
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
	root, err := group.NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	periodKey, _ := group.NewKey()
	tag, _ := group.NewPeriodTag()
	pc, err := group.SignPeriod(group.Tag(root.Cert), tag, &periodKey.PublicKey, 1, now, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	period, _ := pc.Open()
	hubKey, _ := group.NewKey()
	hub, err := group.ServerCertificate(hubKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hub.Leaf.Raw), "cb-") || hub.Leaf.Subject.CommonName != group.ServerCertificateName {
		t.Fatalf("the hub's certificate names a device: %v", hub.Leaf.Subject)
	}
	rogueKey, _ := group.NewKey()
	keyHash := func(k *ecdsa.PrivateKey) group.KeyHash {
		t.Helper()
		spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(spki)
	}
	sign := func(p *group.CredentialBody, key *ecdsa.PrivateKey, v uint64) group.Credential {
		t.Helper()
		c, err := group.SignHubs(p, []group.KeyHash{keyHash(hubKey)}, nil, v, key)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	wg, _ := ecdh.X25519().GenerateKey(rand.Reader)
	register := func(f *Forwarder, pin string, cert tls.Certificate, auth hubAuth) answer {
		t.Helper()
		return rawRegister(t, f, pin, cert, wg.PublicKey().Bytes(), wg, auth)
	}
	creds := func(cs ...group.Credential) hubAuth { return hubAuth{creds: cs} }

	if a := register(f, pin, hub, creds(sign(period, periodKey, 10))); a.Error != "" || a.ID == 0 {
		t.Fatalf("the hub with its credential: %+v", a)
	}
	other, _ := group.ServerCertificate(rogueKey)
	if a := register(f, pin, other, creds(sign(period, periodKey, 10))); !strings.Contains(a.Error, "does not list") {
		t.Errorf("a key the credential does not list: %+v", a)
	}
	old := *period
	old.ExpiresMS = now.Add(-time.Hour).UnixMilli()
	if a := register(f, pin, hub, creds(sign(&old, periodKey, 11))); !strings.Contains(a.Error, "expired") {
		t.Errorf("an expired credential: %+v", a)
	}
	if a := register(f, pin, hub, creds(sign(period, periodKey, 9))); !strings.Contains(a.Error, "older") {
		t.Errorf("an older credential: %+v", a)
	}
	if a := register(f, pin, hub, creds(sign(period, rogueKey, 12))); !strings.Contains(a.Error, "first") {
		t.Errorf("a credential another key signed for the tag: %+v", a)
	}
	if a := register(f, pin, hub, creds(sign(period, periodKey, 12), pc)); !strings.Contains(a.Error, "no hubs' credential") {
		t.Errorf("a period sent to the forwarder: %+v", a)
	}
	withCA := tls.Certificate{Certificate: [][]byte{hub.Certificate[0], root.Cert.Raw}, PrivateKey: hubKey, Leaf: hub.Leaf}
	if a := register(f, pin, withCA, creds(sign(period, periodKey, 13))); a.Error == "" {
		t.Errorf("a server certificate with a group CA: %+v", a)
	}

	// After a restart on the same state the older credential and the other
	// key stay refused. The forwarder writes its state when it stops.
	f.Close()
	g, gpin := startForwarderWith(t, Config{Cert: fcert, StateFile: state})
	if a := register(g, gpin, hub, creds(sign(period, periodKey, 9))); !strings.Contains(a.Error, "older") {
		t.Errorf("an older credential after a restart: %+v", a)
	}
	if a := register(g, gpin, hub, creds(sign(period, rogueKey, 20))); !strings.Contains(a.Error, "first") {
		t.Errorf("another key after a restart: %+v", a)
	}
	if a := register(g, gpin, hub, creds(sign(period, periodKey, 20))); a.Error != "" {
		t.Errorf("a newer credential after a restart: %+v", a)
	}

	// The state names neither the period's tag nor its key, nor the group.
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	pk := keyHash(periodKey)
	for _, c := range []string{tag, hex.EncodeToString(pk[:]), group.Tag(root.Cert)} {
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
