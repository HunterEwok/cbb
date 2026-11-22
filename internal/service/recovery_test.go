// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

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

// TestFFIPhoneChangeRoot: the Aurora app, a member of a computer root's
// group of 0.6, becomes the group's root with the recovery sheet once the
// root is lost (change_preview and change_root; docs/protocol.md, section
// 10, rule 33): it shows who stays first, signs the change with the
// recovery key and its new root key, the computer follows it, and it then
// signs as the root. On 0.6 the root changes only so (D-117, D-125): a
// takeover is refused with the way that is left, and a new phone joins
// afterwards through the new root's window.
func TestFFIPhoneChangeRoot(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	sheet := newGroup(t, pi)
	pairWith(t, pi, a)
	other := startService(t, &h, "other")
	otherSheet := newGroup(t, other)
	next, in, _ := phoneJoins(t, bin, pi, "-name", "aurora", "-dir", t.TempDir(), "-peer", a.addr())
	waitFor(t, "a lists the phone", func() bool { return strings.Contains(listed(a.devices(t)), "aurora") })
	newRoot := func(req map[string]any) string {
		t.Helper()
		b, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(in, "NEWROOT "+string(b))
		return next("NEWROOTED ")
	}
	text := func(s string) map[string]any { return map[string]any{"text": s} }
	if got := newRoot(map[string]any{"action": "take_over", "device": "pi"}); !strings.Contains(got, "recovery key") {
		t.Errorf("a takeover on 0.6: %s", got)
	}
	if got := newRoot(map[string]any{"action": "change_preview", "recovery": text("a typo")}); !strings.Contains(got, "needs a newer cbb") {
		t.Errorf("a typo: %s", got)
	}
	if got := newRoot(map[string]any{"action": "change_root", "recovery": text(otherSheet)}); !strings.Contains(got, "another group") {
		t.Errorf("a sheet of another group: %s", got)
	}
	if got := newRoot(map[string]any{"action": "change_root", "recovery": text(sheet), "leave_out": []string{"aurora"}}); !strings.Contains(got, "stays in the group") {
		t.Errorf("a change that leaves out the phone itself: %s", got)
	}

	pi.stop()
	var preview struct {
		OK struct {
			Rows []struct {
				Name    string `json:"name"`
				Outcome string `json:"outcome"`
			} `json:"rows"`
			Waiting bool `json:"waiting"`
		} `json:"ok"`
	}
	got := newRoot(map[string]any{"action": "change_preview", "recovery": map[string]any{"qr": sheet}, "leave_out": []string{"pi"}})
	if err := json.Unmarshal([]byte(got), &preview); err != nil || preview.OK.Waiting {
		t.Fatalf("who stays: %s", got)
	}
	outcomes := map[string]string{}
	for _, r := range preview.OK.Rows {
		outcomes[r.Name] = r.Outcome
	}
	if len(outcomes) != 2 || outcomes["pi"] != "out" || outcomes["a"] != "stays" {
		t.Fatalf("who stays: %s", got)
	}
	if got := newRoot(map[string]any{"action": "change_root", "recovery": text(sheet), "leave_out": []string{"pi"}}); !strings.Contains(got, `"seq"`) {
		t.Fatalf("changing the root: %s", got)
	}
	waitFor(t, "a follows the new root", rootIs(t, a, "aurora"))
	waitFor(t, "pi is out of the group", func() bool { return !strings.Contains(listed(a.devices(t)), "pi") })
	if got := newRoot(map[string]any{"action": "change_root", "recovery": text(sheet)}); !strings.Contains(got, "root already") {
		t.Errorf("the new root changed the root again: %s", got)
	}
	// It signs as the root now.
	fmt.Fprintln(in, `MANAGE {"action":"rename","device":"a","name":"desk"}`)
	if got := next("MANAGED "); !strings.HasPrefix(got, `{"ok":`) {
		t.Fatalf("renaming as the new root: %s", got)
	}
	waitFor(t, "a takes the new root's name for it", func() bool { return strings.Contains(listed(a.devices(t)), "desk") })
}
