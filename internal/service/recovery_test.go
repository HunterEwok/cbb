// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// addRecovery gives the group of the stopped root its recovery key, as a
// root phone makes one: an admin CA under the root for a new key and the
// recovery record that names it, in the root's records. It returns the
// sheet the key's QR code gives.
func addRecovery(t *testing.T, root *testService) *recoverySheet {
	t.Helper()
	id, err := group.Load(root.dir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := id.RootCA()
	cert, err := ca.IssueAdmin(group.NewDeviceID(), &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recs, err := group.LoadRecords(root.dir, id.GroupCA.Cert)
	if err != nil {
		t.Fatal(err)
	}
	k := group.KeyHashOf(cert)
	r, err := recs.Sign(group.RecordBody{Type: group.RecordRecovery, TimeMS: time.Now().UnixMilli(), Admin: &k, Cert: cert.Raw}, ca.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recs.Add(r); err != nil {
		t.Fatal(err)
	}
	if err := recs.Save(root.dir); err != nil {
		t.Fatal(err)
	}
	return &recoverySheet{Key: key, Admin: k, Cert: cert.Raw, Group: group.Tag(id.GroupCA.Cert)}
}

// TestRecovery checks that a computer of the group that is no admin takes
// the group over with the recovery key when the root is lost (cbb
// recovery): it becomes the root, the others follow, and a handover from it
// lets an admin take the group over at once, without the new root's wait.
func TestRecovery(t *testing.T) {
	var h hub
	var sheet *recoverySheet
	read := func(c *Config) {
		c.readSheet = func(text string) (*recoverySheet, error) {
			if text != "the sheet" {
				return nil, &errRefusedSheet{"check", "the check group does not match"}
			}
			if sheet == nil {
				// A key the group does not know.
				return &recoverySheet{}, nil
			}
			return sheet, nil
		}
	}
	pi := startWith(t, &h, "pi", group.OSLinux, read)
	a := startService(t, &h, "a")
	b := startWith(t, &h, "b", group.OSLinux, read)
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	noClaimWait(t, pi, a, b)
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, "the sheet"); err == nil || !strings.Contains(err.Error(), "no recovery key") {
		t.Errorf("recovery in a group without a recovery key: %v", err)
	}
	pi.stop()
	sheet = addRecovery(t, pi)
	pi = restartService(t, &h, pi)
	waitFor(t, "b holds the recovery key's record", func() bool {
		id, err := group.Load(b.dir)
		if err != nil {
			return false
		}
		recs, err := group.LoadRecords(b.dir, id.GroupCA.Cert)
		return err == nil && recs.State().Recovery != nil
	})
	if _, err := pi.do(t, control.Header{Op: control.OpRecovery}, "the sheet"); err == nil {
		t.Error("the root claimed its own group")
	}
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, "a typo"); err == nil || !strings.Contains(err.Error(), "check group") {
		t.Errorf("a refused text: %v", err)
	}
	other := *sheet
	other.Group = "0123456789abcdef"
	good := sheet
	sheet = &other
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, "the sheet"); err == nil || !strings.Contains(err.Error(), "another group") {
		t.Errorf("a sheet of another group: %v", err)
	}
	sheet = good
	pi.stop()
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, "the sheet"); err != nil {
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
	if _, err := b.do(t, control.Header{Op: control.OpRecovery}, "the sheet"); err == nil {
		t.Error("the new root claimed the group again")
	}

	// The new root waits 72 hours for a claim, but hands the group to an
	// admin at once.
	makeAdmin(t, b, a)
	waitFor(t, "a holds the iPhone CA", func() bool {
		id, err := group.Load(a.dir)
		return err == nil && id.ServesPhone()
	})
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
