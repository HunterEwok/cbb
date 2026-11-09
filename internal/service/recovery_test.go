// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
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

// recoverySheet is what a recovery sheet gives (docs/protocol.md, section
// 10, "The recovery sheet"): the recovery key, its key hash, its admin CA
// and the group's tag.
type recoverySheet struct {
	Key   *ecdsa.PrivateKey
	Admin group.KeyHash
	Cert  []byte // DER
	Group string
}

// qr is the text of the sheet's QR code (docs/protocol.md, section 10,
// "The recovery sheet"; testdata/interop/recovery-sheet.json), which the
// Rust service reads with the core.
func (s *recoverySheet) qr(t *testing.T) string {
	t.Helper()
	scalar, err := s.Key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	k := base64.RawURLEncoding.EncodeToString(scalar)
	return "cbb://recover?g=" + s.Group + "&k=" + k + "&c=" + base64.RawURLEncoding.EncodeToString(s.Cert)
}

// TestRecovery checks that a computer of the group that is no admin takes
// the group over with the recovery key when the root is lost (cbb
// recovery): it becomes the root, the others follow, and a handover from it
// lets an admin take the group over at once, without the new root's wait.
func TestRecovery(t *testing.T) {
	var h hub
	sheetText := func(s *recoverySheet) string { return s.qr(t) }
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	noClaimWait(t, pi, a, b)
	level := pi.status(t).KeyLevel
	if _, err := b.do(t, control.Header{Op: control.OpRecover}, sheetText(newRecoveryKey(t, pi))); err == nil || !strings.Contains(err.Error(), "no recovery key") {
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
	if _, err := pi.do(t, control.Header{Op: control.OpRecover}, sheetText(sheet)); err == nil {
		t.Error("the root claimed its own group")
	}
	if _, err := b.do(t, control.Header{Op: control.OpRecover}, "a typo"); err == nil || !strings.Contains(err.Error(), "not a cbb recovery sheet") {
		t.Errorf("a refused text: %v", err)
	}
	other := *sheet
	other.Group = "0123456789abcdef"
	if _, err := b.do(t, control.Header{Op: control.OpRecover}, sheetText(&other)); err == nil || !strings.Contains(err.Error(), "another group") {
		t.Errorf("a sheet of another group: %v", err)
	}
	pi.stop()
	if _, err := b.do(t, control.Header{Op: control.OpRecover}, sheetText(sheet)); err != nil {
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
	if _, err := b.do(t, control.Header{Op: control.OpRecover}, sheetText(sheet)); err == nil {
		t.Error("the new root claimed the group again")
	}

	// The new root waits 72 hours for a claim, but hands the group to an
	// admin at once.
	// The new root signs the old root's settings again, the key level too.
	waitFor(t, "b keeps the group's key level", func() bool { return b.status(t).KeyLevel == level })
	makeAdmin(t, b, a)
	if _, err := b.do(t, control.Header{Op: control.OpHandOver, Device: "pi"}, ""); err == nil {
		t.Error("handed the group to a device that is no admin")
	}
	if _, err := a.do(t, control.Header{Op: control.OpHandOver, Device: "b"}, ""); err == nil {
		t.Error("an admin that is no root handed the group over")
	}
	if m, err := b.do(t, control.Header{Op: control.OpHandOver, Device: "a"}, ""); err != nil || m.Name != "a" {
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
	if _, err := a.do(t, control.Header{Op: control.OpTakeOver, Device: "b"}, ""); err != nil {
		t.Fatalf("takeover after the handover: %v", err)
	}
	waitFor(t, "a is the root at once", func() bool {
		id, err := group.Load(a.dir)
		return err == nil && id.IsRoot() && len(id.Roots) == 2
	})
}
