// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// credGroup is a group's period as a relay test needs it: the period, its
// key, and the devices' server keys.
type credGroup struct {
	ca     *group.CA
	period group.Credential
	body   *group.CredentialBody
	key    *ecdsa.PrivateKey
}

func newCredGroup(t *testing.T) credGroup {
	t.Helper()
	ca := newGroup(t)
	key, _ := group.NewKey()
	tag, _ := group.NewPeriodTag()
	c, err := group.SignPeriod(group.Tag(ca.Cert), tag, &key.PublicKey, 1, time.Now(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Open()
	return credGroup{ca: ca, period: c, body: b, key: key}
}

// device returns a device that registers with credentials under its
// server key.
func (g credGroup) device(t *testing.T) (device, *ecdsa.PrivateKey) {
	t.Helper()
	sk, _ := group.NewKey()
	cert, err := group.ServerCertificate(sk)
	if err != nil {
		t.Fatal(err)
	}
	wg, _ := tunnel.NewPrivateKey()
	self := group.Pseudonym(group.KeyHashOf(cert.Leaf))
	return device{cert: cert, id: self, key: wg, cred: &Credentialed{Cert: cert, Self: self, Period: g.period, Roots: [][]byte{g.ca.Cert.Raw}}}, sk
}

// sign gives each device the hubs' credential, with admin as the admin,
// and a members' credential that signer signed listing members.
func (g credGroup) sign(t *testing.T, version uint64, admin *ecdsa.PrivateKey, signer *ecdsa.PrivateKey, members []device, to ...*device) {
	t.Helper()
	hubs, err := group.SignHubs(g.body, nil, []group.KeyHash{group.PublicKeyHash(&admin.PublicKey)}, 1, g.key)
	if err != nil {
		t.Fatal(err)
	}
	var list []group.KeyHash
	for _, m := range members {
		list = append(list, group.KeyHashOf(m.cert.Leaf))
	}
	ms, err := group.SignMembers(g.body, list, version, signer)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range to {
		c := *d.cred
		c.Creds = []group.Credential{hubs, ms}
		d.cred = &c
	}
}

// TestCredentialedRelay checks devices that register with their group's
// credentials (docs/protocol.md, section 18): the relay knows them by
// pseudonym, joins them, refuses a device the members' credential does not
// list, drops one a newer members' credential, signed by a listed admin,
// leaves out, refuses another period key for the same tag, and, serving a
// fixed list of groups, takes a device only with its group's root.
func TestCredentialedRelay(t *testing.T) {
	g := newCredGroup(t)
	r, link := startWith(t, Config{Open: true})
	a, aKey := g.device(t)
	b, _ := g.device(t)
	c, _ := g.device(t)
	g.sign(t, 1, aKey, g.key, []device{a, b}, &a, &b, &c)
	if a.id > b.id {
		a, b = b, a
	}
	ja, jb := join(t, link, a), join(t, link, b)
	if got := receive(t, ja.dialed, "a's dial"); got != b.id {
		t.Errorf("a dialed %s, not b's pseudonym %s", got, b.id)
	}
	if got := receive(t, jb.called, "b's call"); got != a.id {
		t.Errorf("b was called by %s, not a's pseudonym %s", got, a.id)
	}

	ctx := context.Background()
	if _, _, _, err := register(ctx, MemberConfig{Link: link, Key: c.key, Cert: func() tls.Certificate { return c.cert }, Credentialed: credOf(c)}); err == nil || !strings.Contains(err.Error(), "does not list") {
		t.Errorf("a device the members' credential does not list: %v", err)
	}
	rogue := g
	rogue.key, _ = group.NewKey()
	d := c
	rogue.sign(t, 9, rogue.key, rogue.key, []device{c}, &d)
	if _, _, _, err := register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert }, Credentialed: credOf(d)}); err == nil || !strings.Contains(err.Error(), "first") {
		t.Errorf("another period key for the tag: %v", err)
	}

	// The admin signs a members' credential without the other device:
	// that one goes.
	admin := a
	if group.KeyHashOf(b.cert.Leaf) == group.PublicKeyHash(&aKey.PublicKey) {
		admin = b
	}
	g.sign(t, 2, aKey, aKey, []device{admin}, &admin)
	tc, _, _, err := register(ctx, MemberConfig{Link: link, Key: admin.key, Cert: func() tls.Certificate { return admin.cert }, Credentialed: credOf(admin)})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	waitFor(t, "the device left out to go", func() bool {
		// The admin, by its link or by the registration above.
		_, n := r.Stats()
		return n == 1
	})

	// A relay for a fixed list of groups wants the root.
	_, closed := startRelay(t, g.ca)
	f, _ := g.device(t)
	g.sign(t, 1, aKey, g.key, []device{f}, &f)
	tc, _, _, err = register(ctx, MemberConfig{Link: closed, Key: f.key, Cert: func() tls.Certificate { return f.cert }, Credentialed: credOf(f)})
	if err != nil {
		t.Fatalf("the group's device on its own relay: %v", err)
	}
	tc.Close()
	_, elsewhere := startRelay(t, newGroup(t))
	if _, _, _, err := register(ctx, MemberConfig{Link: elsewhere, Key: f.key, Cert: func() tls.Certificate { return f.cert }, Credentialed: credOf(f)}); err == nil || !strings.Contains(err.Error(), "not of a group") {
		t.Errorf("a device on another group's relay: %v", err)
	}
}

func credOf(d device) func() (Credentialed, bool) {
	return func() (Credentialed, bool) { return *d.cred, true }
}
