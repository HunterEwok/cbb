// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/piv"
	"github.com/HunterEwok/cbb/internal/piv/pivtest"
)

// addRecovery gives the group of the stopped root its recovery key, as a
// root phone makes one: an admin CA under the root for a new key and the
// recovery record that names it, in the root's records. It returns the
// sheet the key's QR code gives.
func addRecovery(t *testing.T, root *testService) *recoverySheet {
	t.Helper()
	sheet := newRecoveryKey(t, root)
	id, err := group.Load(root.dir)
	if err != nil {
		t.Fatal(err)
	}
	ca := id.RootCA()
	recs, err := group.LoadRecords(root.dir, id.GroupCA.Cert)
	if err != nil {
		t.Fatal(err)
	}
	r, err := recs.Sign(group.RecordBody{Type: group.RecordRecovery, TimeMS: time.Now().UnixMilli(), Admin: &sheet.Admin, Cert: sheet.Cert}, ca.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recs.Add(r); err != nil {
		t.Fatal(err)
	}
	if err := recs.Save(root.dir); err != nil {
		t.Fatal(err)
	}
	return sheet
}

// newRecoveryKey makes a recovery key for the group of root, which may
// run, with its admin CA under the root, and names it in no record.
func newRecoveryKey(t *testing.T, root *testService) *recoverySheet {
	t.Helper()
	id, err := group.Load(root.dir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := id.RootCA().IssueAdmin(group.NewDeviceID(), &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &recoverySheet{Key: key, Admin: group.KeyHashOf(cert), Cert: cert.Raw, Group: group.Tag(id.GroupCA.Cert)}
}

// qr is the text of the sheet's QR code (docs/protocol.md, section 10,
// "The recovery sheet"; testdata/interop/recovery-sheet.json), which the
// Rust service reads with the core.
func (s *recoverySheet) qr() string {
	k := base64.RawURLEncoding.EncodeToString(s.Key.D.FillBytes(make([]byte, 32)))
	return "cbb://recover?g=" + s.Group + "&k=" + k + "&c=" + base64.RawURLEncoding.EncodeToString(s.Cert)
}

// TestRecovery checks that a computer of the group that is no admin takes
// the group over with the recovery key when the root is lost (cbb
// recovery): it becomes the root, the others follow, and a handover from it
// lets an admin take the group over at once, without the new root's wait.
func TestRecovery(t *testing.T) {
	var h hub
	// The Go service reads the sheets the test made without the core,
	// which a test build has not.
	var sheets sync.Map // the QR code's text: *recoverySheet
	read := func(c *Config) {
		c.readSheet = func(text string) (*recoverySheet, error) {
			if s, ok := sheets.Load(text); ok {
				return s.(*recoverySheet), nil
			}
			return nil, &errRefusedSheet{"not_sheet", "this is not a cbb recovery sheet"}
		}
	}
	sheetText := func(s *recoverySheet) string {
		sheets.Store(s.qr(), s)
		return s.qr()
	}
	pi := startEnv(t, &h, "pi", read)
	a := startService(t, &h, "a")
	b := startEnv(t, &h, "b", read)
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	noClaimWait(t, pi, a, b)
	level := pi.status(t).KeyLevel
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, sheetText(newRecoveryKey(t, pi))); err == nil || !strings.Contains(err.Error(), "no recovery key") {
		t.Errorf("recovery in a group without a recovery key: %v", err)
	}
	pi.stop()
	sheet := addRecovery(t, pi)
	pi = restartService(t, &h, pi)
	waitFor(t, "b holds the recovery key's record", func() bool {
		id, err := group.Load(b.dir)
		if err != nil {
			return false
		}
		recs, err := group.LoadRecords(b.dir, id.GroupCA.Cert)
		return err == nil && recs.State().Recovery != nil
	})
	if _, err := pi.do(t, control.Header{Op: control.OpRecovery}, sheetText(sheet)); err == nil {
		t.Error("the root claimed its own group")
	}
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, "a typo"); err == nil || !strings.Contains(err.Error(), "not a cbb recovery sheet") {
		t.Errorf("a refused text: %v", err)
	}
	other := *sheet
	other.Group = "0123456789abcdef"
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, sheetText(&other)); err == nil || !strings.Contains(err.Error(), "another group") {
		t.Errorf("a sheet of another group: %v", err)
	}
	pi.stop()
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, sheetText(sheet)); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	waitFor(t, "b is the root", func() bool {
		id, err := group.Load(b.dir)
		return err == nil && id.IsRoot() && len(id.Roots) == 1 && id.Claim == nil
	})
	waitFor(t, "a follows the new root", func() bool {
		id, err := group.Load(a.dir)
		return err == nil && len(id.Roots) == 1
	})
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, sheetText(sheet)); err == nil {
		t.Error("the new root claimed the group again")
	}

	// The new root waits 72 hours for a claim, but hands the group to an
	// admin at once.
	// The new root signs the old root's settings again, the key level too.
	waitFor(t, "b keeps the group's key level", func() bool { return b.status(t).KeyLevel == level })
	makeAdmin(t, b, a)
	if _, err := b.do(t, control.Header{Op: control.OpHandover, Name: "pi"}, ""); err == nil {
		t.Error("handed the group to a device that is no admin")
	}
	if _, err := a.do(t, control.Header{Op: control.OpHandover, Name: "b"}, ""); err == nil {
		t.Error("an admin that is no root handed the group over")
	}
	if m, err := b.do(t, control.Header{Op: control.OpHandover, Name: "a"}, ""); err != nil || m.Name != "a" {
		t.Fatalf("handover: %+v, %v", m, err)
	}
	waitFor(t, "a holds the handover", func() bool {
		id, err := group.Load(a.dir)
		if err != nil {
			return false
		}
		recs, err := group.LoadRecords(a.dir, id.GroupCA.Cert)
		if err != nil {
			return false
		}
		for _, r := range recs.All() {
			if strings.Contains(string(r.Body), `"type":"handover"`) {
				return true
			}
		}
		return false
	})
	b.stop()
	if _, err := a.do(t, control.Header{Op: control.OpTakeover, Name: "b"}, ""); err != nil {
		t.Fatalf("takeover after the handover: %v", err)
	}
	waitFor(t, "a is the root at once", func() bool {
		id, err := group.Load(a.dir)
		return err == nil && id.IsRoot() && len(id.Roots) == 2
	})
}

// TestRecoveryWithCard checks cbb recovery -yubikey: the recovery key on a
// YubiKey signs the claim, after its PIN, from the slot whose certificate
// is the key's admin CA.
func TestRecoveryWithCard(t *testing.T) {
	var h hub
	var plugged atomic.Pointer[pivtest.Card]
	open := func(c *Config) {
		c.openCard = func(match func(*x509.Certificate) bool) (*piv.Key, error) {
			card := plugged.Load()
			if card == nil {
				return nil, piv.ErrNoCard
			}
			card.Connect()
			for slot := byte(piv.FirstSlot); slot <= piv.LastSlot; slot++ {
				if s, ok := card.Slot(slot); ok && s.Cert != nil && match(s.Cert) {
					if err := piv.Select(card); err != nil {
						return nil, err
					}
					return &piv.Key{Card: card, Slot: slot, Cert: s.Cert}, nil
				}
			}
			return nil, piv.ErrNoKey
		}
	}
	pi := startService(t, &h, "pi")
	b := startWith(t, &h, "b", group.OSLinux, open)
	pairWith(t, pi, b)
	noClaimWait(t, pi, b)
	recoveryCard := control.Header{Op: control.OpRecovery, Name: control.RecoveryCard, Kind: control.KindSecret}
	if _, err := b.do(t, recoveryCard, "123456"); err == nil || !strings.Contains(err.Error(), "no recovery key") {
		t.Errorf("recovery in a group without a recovery key: %v", err)
	}
	pi.stop()
	sheet := addRecovery(t, pi)
	pi = restartService(t, &h, pi)
	waitFor(t, "b holds the recovery key's record", func() bool {
		id, err := group.Load(b.dir)
		if err != nil {
			return false
		}
		recs, err := group.LoadRecords(b.dir, id.GroupCA.Cert)
		return err == nil && recs.State().Recovery != nil
	})
	pi.stop()
	if _, err := b.do(t, recoveryCard, "123456"); err == nil || !strings.Contains(err.Error(), "no YubiKey") {
		t.Errorf("no card: %v", err)
	}
	cert, err := x509.ParseCertificate(sheet.Cert)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	card := pivtest.New(0x82, other, nil)
	plugged.Store(card)
	if _, err := b.do(t, recoveryCard, "123456"); err == nil || !strings.Contains(err.Error(), "no recovery key of the group") {
		t.Errorf("a card without the key: %v", err)
	}
	card.SetSlot(0x83, pivtest.Slot{Key: sheet.Key, Cert: cert})
	if _, err := b.do(t, recoveryCard, "000000"); err == nil || !strings.Contains(err.Error(), "wrong PIN") {
		t.Errorf("a wrong PIN: %v", err)
	}
	if card.Signed() != 0 {
		t.Error("the card signed without its PIN")
	}
	if _, err := b.do(t, recoveryCard, "123456"); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if card.Signed() != 1 || !card.Closed() {
		t.Errorf("the card signed %d times, closed %v", card.Signed(), card.Closed())
	}
	waitFor(t, "b is the root", func() bool {
		id, err := group.Load(b.dir)
		return err == nil && id.IsRoot() && len(id.Roots) == 1 && id.Claim == nil
	})
}

// TestRecoveryCertUnderARoot checks that cbb recovery takes the recovery
// key's admin CA only from a recovery record whose CA a root of the group
// issued: a newer record that another admin signs with a CA of its own for
// the same key counts for nothing, and must not replace the right one.
func TestRecoveryCertUnderARoot(t *testing.T) {
	id, err := group.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := group.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good, err := id.RootCA().IssueAdmin(group.NewDeviceID(), &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bad, err := stranger.RootCA().IssueAdmin(group.NewDeviceID(), &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	k := group.KeyHashOf(good)
	if group.KeyHashOf(bad) != k {
		t.Fatal("the two admin CAs differ in key")
	}
	at := time.Now().UnixMilli()
	sign := func(cert *x509.Certificate, signer *ecdsa.PrivateKey, ms int64) group.Record {
		r, err := authority.Sign(group.RecordBody{Type: group.RecordRecovery, Group: group.Tag(id.GroupCA.Cert), Seq: 1, TimeMS: ms, Admin: &k, Cert: cert.Raw}, signer, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	rs := []group.Record{sign(good, id.RootCA().Key.(*ecdsa.PrivateKey), at), sign(bad, stranger.RootCA().Key.(*ecdsa.PrivateKey), at+1000)}
	roots := []*x509.Certificate{id.Root()}
	if got := recoveryCert(rs, roots, k); !bytes.Equal(got, good.Raw) {
		t.Error("the admin CA came from a record whose CA no root of the group issued")
	}
	if underARoot(bad.Raw, roots, k) || !underARoot(good.Raw, roots, k) {
		t.Error("underARoot does not tell the root's admin CA from another")
	}
}
