// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

func phoneInfo(t *testing.T) (Info, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Info{Name: "phone", OS: group.OSiOS, AdminKey: spki}, key
}

// TestPhoneJoinsTheRoot checks that a phone joins a computer's group
// through its root (docs/protocol.md, section 6, "A phone joins a
// computer's group"): the Welcome carries an admin CA under the root for
// the admin key the phone offered, and the result names it, when the
// window was opened to make admins (cbb pair -admin).
func TestPhoneJoinsTheRoot(t *testing.T) {
	root, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	f := fixtureWith(t, root, true)
	info, key := phoneInfo(t)
	r, served := startRaw(t, f, info, f.code)
	last := r.confirm()
	if last.Welcome == nil || last.Welcome.AdminCA == nil {
		t.Fatalf("the Welcome to a phone carries no admin CA: %+v", last)
	}
	writeFrame(r.tc, &frame{OK: true})
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(last.Welcome.AdminCA)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || ca.CheckSignatureFrom(f.admin.Root()) != nil || !group.SameKey(key, ca.PublicKey) {
		t.Error("the admin CA is not the root's for the phone's admin key")
	}
	res, err := f.window.Result()
	if err != nil || !res.Info.Phone() || res.AdminCA == nil || !res.AdminCA.Equal(ca) {
		t.Errorf("Result = %+v, %v", res, err)
	}
	// A phone without an admin key, as a TV, joins as a member.
	f = newFixture(t)
	r, served = startRaw(t, f, Info{Name: "tv", OS: group.OSAndroid}, f.code)
	if last := r.confirm(); last.Welcome == nil || last.Welcome.AdminCA != nil {
		t.Errorf("a phone without an admin key: %+v", last)
	}
	writeFrame(r.tc, &frame{OK: true})
	<-served
}

// TestPhoneAdminNeedsTheWindow checks that a plain window of the root
// refuses a phone that offers an admin key: the code alone makes no admin.
func TestPhoneAdminNeedsTheWindow(t *testing.T) {
	f := newFixture(t)
	info, _ := phoneInfo(t)
	r, served := startRaw(t, f, info, f.code)
	if last := r.confirm(); last.Welcome != nil || last.Error != "refused" {
		t.Errorf("a plain window's answer to a phone with an admin key: %+v", last)
	}
	if err := <-served; !errors.Is(err, ErrAdminNotAllowed) {
		t.Errorf("Serve: %v", err)
	}
	// Only the root opens a window that makes admins.
	admin, _ := computerAdmin(t)
	if _, err := Open(admin, NewCode(), Options{Admins: true}); !errors.Is(err, ErrPhoneNeedsRoot) {
		t.Errorf("an admin computer opened a window for admins: %v", err)
	}
}

// TestPhoneNeedsTheRoot checks that an admin computer refuses a phone:
// only the root makes it an admin.
func TestPhoneNeedsTheRoot(t *testing.T) {
	admin, _ := computerAdmin(t)
	clk := &clock{up: time.Hour}
	code := NewCode()
	w, err := Open(admin, code, Options{Now: func() time.Time { return t0 }, Uptime: clk.uptime, AfterFunc: clk.afterFunc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	f := &fixture{admin: admin, window: w, code: code, clock: clk}
	info, _ := phoneInfo(t)
	r, served := startRaw(t, f, info, code)
	if last := r.confirm(); last.Welcome != nil || last.Error != "refused" {
		t.Errorf("an admin computer's answer to a phone: %+v", last)
	}
	if err := <-served; !errors.Is(err, ErrPhoneNeedsRoot) {
		t.Errorf("Serve: %v", err)
	}
}

func TestPhoneInfo(t *testing.T) {
	info, _ := phoneInfo(t)
	if err := info.check(); err != nil {
		t.Errorf("a phone's description: %v", err)
	}
	for _, bad := range []Info{
		{Name: "x", OS: group.OSLinux, AdminKey: info.AdminKey},
		{Name: "x", OS: group.OSiOS, AdminKey: []byte{1, 2, 3}},
		{Name: "x", OS: group.OSiOS, Role: RoleLite},
	} {
		if err := bad.check(); err == nil {
			t.Errorf("%+v passed the check", bad)
		}
	}
}
