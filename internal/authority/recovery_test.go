// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority_test

import (
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// recovery is a recovery record naming the admin key name, with its admin
// CA.
func (w *world) recovery(name string) authority.Body {
	k := w.adminKey(name)
	return authority.Body{Type: authority.TypeRecovery, Admin: &k, Cert: w.cas[name].Raw}
}

// recoveryWorld is a group whose root made the offline key K its recovery
// key: an admin CA for K and a recovery record naming it, no device.
func recoveryWorld(t *testing.T) *world {
	w := newWorld(t)
	w.admin("K", "root")
	w.sign("recovery K", "root", w.recovery("K"), nil)
	return w
}

// TestRecoveryKey: the recovery key may only claim the group, with the
// delay the root set for admins, and the root cancels or removes it as it
// does an admin.
func TestRecoveryKey(t *testing.T) {
	w := recoveryWorld(t)
	k := w.adminKey("K")
	s := w.evalAll(nil)
	if s.Recovery == nil || *s.Recovery != k || findDevice(s, w.ids["K"]) != nil {
		t.Fatalf("the state should name the recovery key and no device of it: %s", mustEncode(t, s))
	}

	// It admits no device and signs no settings.
	d := w.device("K", "laptop", "full", nil, nil, false)
	st := w.sign("K's settings", "K", authority.Body{Type: authority.TypeSettings, TakeoverDelayMS: ptr(int64(0))}, nil)
	s = w.evalAll(nil)
	if findDevice(s, w.ids["laptop"]) != nil || ignoredWhy(s, d.ID()) != authority.WhyPower || ignoredWhy(s, st.ID()) != authority.WhyPower {
		t.Fatalf("the recovery key should have no power but takeover: %s", mustEncode(t, s))
	}

	// Its claim waits the delay and takes effect.
	c := w.claim("K", "R2", nil)
	first := map[authority.Hash]int64{c.ID(): 0}
	w.now = authority.DefaultDelay - 1
	if s = w.evalAll(first); len(s.Roots) != 1 || claimState(s, c.ID()) != "pending" {
		t.Fatalf("the claim should wait: %s", mustEncode(t, s))
	}
	w.now = authority.DefaultDelay
	if s = w.evalAll(first); len(s.Roots) != 2 || claimState(s, c.ID()) != "effective" {
		t.Fatalf("the claim should take effect: %s", mustEncode(t, s))
	}
	// The root comes back and cancels it.
	w.sign("cancel", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{c.ID()}}, nil)
	if s = w.evalAll(first); len(s.Roots) != 1 || claimState(s, c.ID()) != "cancelled" {
		t.Fatalf("the root should cancel the claim: %s", mustEncode(t, s))
	}
}

// TestRecoveryDelay: the recovery key waits the delay of the root's
// settings, as an admin does.
func TestRecoveryDelay(t *testing.T) {
	w := newWorld(t)
	w.sign("settings", "root", authority.Body{Type: authority.TypeSettings, TakeoverDelayMS: ptr(int64(1000))}, nil)
	w.admin("K", "root")
	w.sign("recovery K", "root", w.recovery("K"), nil)
	c := w.claim("K", "R2", nil)
	first := map[authority.Hash]int64{c.ID(): 0}
	w.now = 999
	if s := w.evalAll(first); claimState(s, c.ID()) != "pending" {
		t.Fatalf("the claim should wait the root's delay: %s", mustEncode(t, s))
	}
	w.now = 1000
	if s := w.evalAll(first); len(s.Roots) != 2 {
		t.Fatalf("the claim should take effect after the root's delay: %s", mustEncode(t, s))
	}
}

// TestRecoveryRemoved: a removed recovery key leaves the state, and its
// claim does not count.
func TestRecoveryRemoved(t *testing.T) {
	w := recoveryWorld(t)
	w.sign("remove K", "root", revoke(w.adminKey("K")), nil)
	c := w.claim("K", "R2", nil)
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if s.Recovery != nil || len(s.Roots) != 1 || claimState(s, c.ID()) == "effective" {
		t.Fatalf("a removed recovery key should not take the group: %s", mustEncode(t, s))
	}
}

// TestRecoveryReplaced: a newer recovery record names another key; the
// old one can no longer claim.
func TestRecoveryReplaced(t *testing.T) {
	w := recoveryWorld(t)
	w.admin("K2", "root")
	k2 := w.adminKey("K2")
	w.sign("recovery K2", "root", w.recovery("K2"), nil)
	c := w.claim("K", "R2", nil)
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if s.Recovery == nil || *s.Recovery != k2 || len(s.Roots) != 1 || ignoredWhy(s, c.ID()) != authority.WhyPower {
		t.Fatalf("only the newest recovery key should count: %s", mustEncode(t, s))
	}
}

// TestRecoveryByAdmin: an admin cannot name a recovery key.
func TestRecoveryByAdmin(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.admin("K", "root")
	r := w.sign("recovery by A", "A", w.recovery("K"), nil)
	c := w.claim("K", "R2", nil)
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if s.Recovery != nil || ignoredWhy(s, r.ID()) != authority.WhyPower || len(s.Roots) != 1 || ignoredWhy(s, c.ID()) != authority.WhyPower {
		t.Fatalf("an admin's recovery record should not count: %s", mustEncode(t, s))
	}
}

// TestRecoveryCertFromAnotherRoot: a recovery record whose cert another
// root signed names no recovery key.
func TestRecoveryCertFromAnotherRoot(t *testing.T) {
	w := newWorld(t)
	other, err := group.NewRootCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w.roots["other"] = other
	w.admin("K", "other")
	w.sign("recovery K", "root", w.recovery("K"), nil)
	if s := w.evalAll(nil); s.Recovery != nil {
		t.Fatalf("a cert from another root should name no recovery key: %s", mustEncode(t, s))
	}
}

// TestRecoveryCertMismatch: a recovery record's cert must be its admin
// key's.
func TestRecoveryCertMismatch(t *testing.T) {
	w := newWorld(t)
	w.admin("K", "root")
	w.admin("K2", "root")
	b := w.recovery("K")
	b.Cert = w.cas["K2"].Raw
	b.Group, b.Seq, b.TimeMS = tag, 1, 1
	if _, err := b.Encode(); err == nil {
		t.Fatal("a recovery record with another key's cert should not encode")
	}
	b.Cert = nil
	if _, err := b.Encode(); err == nil {
		t.Fatal("a recovery record without cert should not encode")
	}
}

// TestHandover: the root hands the group to an admin, whose claim then
// takes effect at once; a claim made before the handover, or by another
// admin, still waits, and the root still cancels it.
func TestHandover(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	early := w.claim("A", "R0", nil)
	a := w.adminKey("A")
	w.sign("handover A", "root", authority.Body{Type: authority.TypeHandover, Admin: &a}, nil)
	if s := w.evalAll(nil); claimState(s, early.ID()) != "pending" {
		t.Fatalf("a claim made before the handover should wait: %s", mustEncode(t, s))
	}

	w = newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	a = w.adminKey("A")
	w.sign("handover A", "root", authority.Body{Type: authority.TypeHandover, Admin: &a}, nil)
	other := w.fork()
	c := w.claim("A", "R2", nil)
	s := w.evalAll(nil)
	if len(s.Roots) != 2 || claimState(s, c.ID()) != "effective" {
		t.Fatalf("the claim of the admin the root handed the group to should take effect at once: %s", mustEncode(t, s))
	}
	w.sign("cancel", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{c.ID()}}, nil)
	if s = w.evalAll(nil); len(s.Roots) != 1 || claimState(s, c.ID()) != "cancelled" {
		t.Fatalf("the root should still cancel it: %s", mustEncode(t, s))
	}

	cb := other.claim("B", "R3", nil)
	if s = other.evalAll(nil); claimState(s, cb.ID()) != "pending" {
		t.Fatalf("another admin's claim should wait: %s", mustEncode(t, s))
	}
}

// TestHandoverReplaced: a newer handover names another admin; the first
// one's claim waits again. An admin's handover counts for nothing.
func TestHandoverReplaced(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	a, b := w.adminKey("A"), w.adminKey("B")
	w.sign("handover A", "root", authority.Body{Type: authority.TypeHandover, Admin: &a}, nil)
	w.sign("handover B", "root", authority.Body{Type: authority.TypeHandover, Admin: &b}, nil)
	byB := w.sign("handover by B", "B", authority.Body{Type: authority.TypeHandover, Admin: &a}, nil)
	c := w.claim("A", "R2", nil)
	s := w.evalAll(nil)
	if claimState(s, c.ID()) != "pending" || ignoredWhy(s, byB.ID()) != authority.WhyPower {
		t.Fatalf("only the root's newest handover should count: %s", mustEncode(t, s))
	}
}
