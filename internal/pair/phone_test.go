// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	r, served := startRawProving(t, f, info, f.code, key)
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
	info, key := phoneInfo(t)
	r, served := startRawProving(t, f, info, f.code, key)
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

// TestPhoneNeedsTheRoot checks that an admin computer refuses a phone that
// offers an admin key: only the root makes it an admin.
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
	info, key := phoneInfo(t)
	r, served := startRawProving(t, f, info, code, key)
	if last := r.confirm(); last.Welcome != nil || last.Error != "refused" {
		t.Errorf("an admin computer's answer to a phone: %+v", last)
	}
	if err := <-served; !errors.Is(err, ErrPhoneNeedsRoot) {
		t.Errorf("Serve: %v", err)
	}
}

// TestPhoneMemberThroughAdmin checks that an admin computer admits a phone
// that offers no admin key, such as the Aurora OS app, as a member.
func TestPhoneMemberThroughAdmin(t *testing.T) {
	admin, _ := computerAdmin(t)
	clk := &clock{up: time.Hour}
	code := NewCode()
	w, err := Open(admin, code, Options{Now: func() time.Time { return t0 }, Uptime: clk.uptime, AfterFunc: clk.afterFunc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	f := &fixture{admin: admin, window: w, code: code, clock: clk}
	r, served := startRaw(t, f, Info{Name: "aurora phone", OS: group.OSAurora}, code)
	last := r.confirm()
	if last.Welcome == nil || last.Error != "" {
		t.Fatalf("an admin computer's answer to a phone without an admin key: %+v", last)
	}
	if last.Welcome.AdminCA != nil {
		t.Errorf("the phone got an admin CA from an admin computer")
	}
	writeFrame(r.tc, &frame{OK: true})
	if err := <-served; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	res, err := w.Result()
	if err != nil || res.Info.OS != group.OSAurora || !res.Info.Phone() || res.AdminCA != nil {
		t.Fatalf("the window admitted %+v, %v", res, err)
	}
}

func TestPhoneInfo(t *testing.T) {
	info, _ := phoneInfo(t)
	info.AdminProof = []byte{1}
	if err := info.check(); err != nil {
		t.Errorf("a phone's description: %v", err)
	}
	for _, bad := range []Info{
		{Name: "x", OS: group.OSLinux, AdminKey: info.AdminKey},
		{Name: "x", OS: group.OSiOS, AdminKey: []byte{1, 2, 3}},
		{Name: "x", OS: group.OSiOS, Role: RoleLite},
		{Name: "x", OS: group.OSiOS, AdminKey: info.AdminKey},
		{Name: "x", OS: group.OSiOS, AdminProof: []byte{1}},
	} {
		if err := bad.check(); err == nil {
			t.Errorf("%+v passed the check", bad)
		}
	}
}

// TestPhoneAdminProof checks that the root makes a phone an admin only
// when its admin key signed the proof for this very connection, and the
// key is not one the group knows already, such as the recovery key.
func TestPhoneAdminProof(t *testing.T) {
	root, err := group.Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	info, key := phoneInfo(t)
	other, otherKey := phoneInfo(t)
	for name, try := range map[string]func(f *fixture) (*rawJoiner, chan error){
		"no proof": func(f *fixture) (*rawJoiner, chan error) {
			i := info
			i.AdminProof = []byte{1}
			return startRaw(t, f, i, f.code)
		},
		"another key's proof": func(f *fixture) (*rawJoiner, chan error) {
			_, k := phoneInfo(t)
			return startRawProving(t, f, info, f.code, k)
		},
		"a proof for another connection": func(f *fixture) (*rawJoiner, chan error) {
			h := sha256.Sum256(AdminProofMessage(make([]byte, 32)))
			sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
			if err != nil {
				t.Fatal(err)
			}
			i := info
			i.AdminProof = sig
			return startRaw(t, f, i, f.code)
		},
	} {
		f := fixtureWith(t, root, true)
		r, served := try(f)
		if last := r.confirm(); last.Welcome != nil || last.Error != "refused" {
			t.Errorf("%s: %+v", name, last)
		}
		if err := <-served; !errors.Is(err, ErrAdminProof) {
			t.Errorf("%s: Serve: %v", name, err)
		}
	}
	// A key the records name already.
	known := group.KeyHash(sha256.Sum256(other.AdminKey))
	clk := &clock{up: time.Hour}
	code := NewCode()
	w, err := Open(root, code, Options{Now: func() time.Time { return t0 }, Uptime: clk.uptime, AfterFunc: clk.afterFunc, Admins: true,
		KnownKey: func(h group.KeyHash) bool { return h == known }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	f := &fixture{admin: root, window: w, code: code, clock: clk}
	r, served := startRawProving(t, f, other, code, otherKey)
	if last := r.confirm(); last.Welcome != nil || last.Error != "refused" {
		t.Errorf("a known admin key: %+v", last)
	}
	if err := <-served; !errors.Is(err, ErrAdminProof) {
		t.Errorf("a known admin key: Serve: %v", err)
	}
}
