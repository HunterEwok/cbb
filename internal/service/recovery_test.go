// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

// newGroup makes s the root of a new group of 0.6 (cbb new) and returns
// the text of the recovery sheet's QR code, which cbb new shows once.
func newGroup(t *testing.T, s *testService) string {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpNew}, "")
	if err != nil {
		t.Fatalf("new on %s: %v", s.name, err)
	}
	var sheet struct {
		QR string `json:"qr"`
	}
	if err := json.Unmarshal(m.Payload, &sheet); err != nil || sheet.QR == "" {
		t.Fatalf("the recovery sheet of cbb new on %s: %v, %q", s.name, err, m.Payload)
	}
	return sheet.QR
}

// recoverWith has s claim its group with the recovery sheet's text,
// leaving out the devices named.
func recoverWith(t *testing.T, s *testService, sheet string, leave ...string) error {
	t.Helper()
	_, err := s.do(t, control.Header{Op: control.OpRecover, Leave: leave}, sheet)
	return err
}

// recoverOn has s claim its group with the recovery sheet's text, leaving
// out the devices named, and starts its service again once it ended to
// sign with its new root key, as systemd would.
func recoverOn(t *testing.T, h *hub, s *testService, sheet string, leave ...string) *testService {
	t.Helper()
	if err := recoverWith(t, s, sheet, leave...); err != nil {
		t.Fatalf("recovery on %s: %v", s.name, err)
	}
	select {
	case err := <-s.done:
		if !errors.Is(err, ErrRestart) {
			t.Fatalf("%s ended with %v after the recovery", s.name, err)
		}
		s.cancel = nil
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not restart after the recovery", s.name)
	}
	return restartService(t, h, s)
}

// TestRecovery checks that a computer of the group that is no admin takes
// the group over with the recovery key when the root is lost (cbb
// recovery): it becomes the root, the others follow, the group keeps its
// key level, and the old root's admin is an admin no more. On the records
// of 0.6 the root changes only so (D-117): a handover from the new root and
// a takeover of it are refused with the way that is left.
func TestRecovery(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	sheet := newGroup(t, pi)
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	makeAdmin(t, pi, a)
	level := pi.status(t).KeyLevel
	other := startService(t, &h, "other")
	otherSheet := newGroup(t, other)

	if err := recoverWith(t, pi, sheet); err == nil || !strings.Contains(err.Error(), "root already") {
		t.Errorf("the root claimed its own group: %v", err)
	}
	// Text outside the sheet's alphabet is no sheet; words within it read
	// as a later version's first character (docs/protocol.md, section 10).
	if err := recoverWith(t, b, "https://example.com/"); err == nil || !strings.Contains(err.Error(), "not a cbb recovery sheet") {
		t.Errorf("a refused text: %v", err)
	}
	if err := recoverWith(t, b, "a typo"); err == nil || !strings.Contains(err.Error(), "needs a newer cbb") {
		t.Errorf("a typo: %v", err)
	}
	if err := recoverWith(t, b, otherSheet); err == nil || !strings.Contains(err.Error(), "another group") {
		t.Errorf("a sheet of another group: %v", err)
	}
	if err := recoverWith(t, b, sheet, "b"); err == nil || !strings.Contains(err.Error(), "stays in the group") {
		t.Errorf("a recovery that leaves out the new root itself: %v", err)
	}
	pi.stop()
	b = recoverOn(t, &h, b, sheet)
	waitFor(t, "b is the root", rootIs(t, b, "b"))
	waitFor(t, "a follows the new root", rootIs(t, a, "b"))
	if err := recoverWith(t, b, sheet); err == nil || !strings.Contains(err.Error(), "root already") {
		t.Errorf("the new root claimed the group again: %v", err)
	}
	// The new root signs the old root's settings again, the key level too.
	waitFor(t, "b keeps the group's key level", func() bool { return b.status(t).KeyLevel == level })

	// A change of root revokes the old root's admin keys for good.
	waitFor(t, "a is an admin no more", func() bool { return !a.isAdmin(t) })
	if _, err := b.do(t, control.Header{Op: control.OpHandOver, Device: "a"}, ""); err == nil || !strings.Contains(err.Error(), "cbb recovery") {
		t.Errorf("a handover on the new root: %v", err)
	}
	b.stop()
	if _, err := a.do(t, control.Header{Op: control.OpTakeOver, Device: "b"}, ""); err == nil || !strings.Contains(err.Error(), "cbb recovery") {
		t.Errorf("a takeover by the old root's admin: %v", err)
	}
	waitFor(t, "b is still the root on a", rootIs(t, a, "b"))
}

// TestFFIPhoneRestore: a new Aurora phone restores a computer's group with
// the recovery sheet once the root is lost (cbb_restore): it takes and
// checks the records from a member on a connection that carries records
// only, starts its member with the certificate the recovery key issued it,
// claims the group with the sheet (recover_with_sheet), and becomes the root
// once the claim takes effect.
func TestFFIPhoneRestore(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	pairWith(t, pi, a)
	noClaimWait(t, pi, a)
	pi.stop()
	sheet := addRecovery(t, pi)
	pi = restartService(t, &h, pi)
	waitFor(t, "a holds the recovery key's record", func() bool {
		id, err := group.Load(a.dir)
		if err != nil {
			return false
		}
		recs, err := group.LoadRecords(a.dir, id.GroupCA.Cert)
		return err == nil && recs.State().Recovery != nil
	})
	pi.stop()
	id, err := group.Load(a.dir)
	if err != nil {
		t.Fatal(err)
	}

	// The typed key is not enough, and a sheet of another group finds none.
	next, _ := phoneOnLinux(t, bin, "-name", "typo", "-restore", "a typo", "-peer", a.addr())
	if got := next("RESTORE FAILED "); !strings.Contains(got, "not a cbb recovery sheet") {
		t.Errorf("a typed text: %s", got)
	}
	other := *sheet
	other.Group = "0123456789abcdef"
	next, _ = phoneOnLinux(t, bin, "-name", "other", "-restore", other.qr(t), "-peer", a.addr())
	if got := next("RESTORE FAILED "); !strings.Contains(got, "another group") {
		t.Errorf("a sheet of another group: %s", got)
	}

	next, in := phoneOnLinux(t, bin, "-name", "new phone", "-restore", sheet.qr(t), "-dir", t.TempDir(), "-peer", a.addr())
	restored := strings.Fields(next("Restored "))
	if len(restored) != 2 || restored[1] != group.Tag(id.GroupCA.Cert) {
		t.Fatalf("the restored group: %q, not %s", restored, group.Tag(id.GroupCA.Cert))
	}
	manage := func(req string) map[string]any {
		fmt.Fprintln(in, "MANAGE "+req)
		var m map[string]any
		got := next("MANAGED ")
		if err := json.Unmarshal([]byte(got), &m); err != nil {
			t.Fatalf("the answer %q: %v", got, err)
		}
		return m
	}
	ok := func(m map[string]any) map[string]any {
		t.Helper()
		o, ok := m["ok"].(map[string]any)
		if !ok {
			t.Fatalf("refused: %v", m)
		}
		return o
	}
	root, _ := ok(manage(`{"action":"root_ca"}`))["root_ca"].(string)
	if root == "" {
		t.Fatal("no root CA")
	}
	if m := manage(`{"action":"recover_with_sheet","sheet":"a typo","root_ca":"` + root + `"}`); m["error"] == nil {
		t.Fatalf("claimed with a typed text: %v", m)
	}
	ok(manage(`{"action":"recover_with_sheet","sheet":"` + sheet.qr(t) + `","root_ca":"` + root + `"}`))
	waitFor(t, "the claim takes effect", func() bool {
		return ok(manage(`{"action":"finish_takeover","root_ca":"` + root + `","name":"new phone","os":"aurora"}`))["state"] == "effective"
	})
	waitFor(t, "the computer lists the new phone as the root", func() bool {
		for _, d := range a.devices(t) {
			if d.Name == "new phone" {
				return d.Root && d.Role == group.RolePhone
			}
		}
		return false
	})
}
