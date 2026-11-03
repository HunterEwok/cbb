// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/hlc"
	"github.com/HunterEwok/clipboardbridge/internal/node"
)

func TestSyncModes(t *testing.T) {
	var h hub
	newDevice := func(c *Config) { c.newMode = nil } // as outside the tests: own
	a := startWith(t, &h, "alpha", group.OSLinux, newDevice)
	b := startWith(t, &h, "beta", group.OSLinux, newDevice)
	if _, err := a.do(t, control.Header{Op: control.OpMode, Name: "shared"}, ""); err == nil {
		t.Error("a device in no group took a sync mode")
	}
	pairWith(t, a, b)
	for _, s := range []*testService{a, b} {
		if m := s.status(t).Mode; m != "own" {
			t.Fatalf("%s: a new device's mode is %q, want own", s.name, m)
		}
	}
	waitFor(t, "a connected to b", func() bool { return len(a.status(t).Peers) == 1 })

	// A deliberate copy reaches the group in own mode, and cbb paste on
	// the other device prints the group's text.
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from alpha"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta has the group's text", func() bool { return b.paste(t) == "from alpha" })

	if _, err := b.do(t, control.Header{Op: control.OpMode, Name: "everything"}, ""); err == nil {
		t.Error("an unknown mode was taken")
	}
	m, err := b.do(t, control.Header{Op: control.OpMode, Name: "receive"}, "")
	if err != nil || m.Status.Mode != "receive" {
		t.Fatalf("mode receive: %v, %+v", err, m)
	}
	// The mode is saved, and the others see it in the hello after a restart.
	b.stop()
	b = restartService(t, &h, b)
	if m := b.status(t).Mode; m != "receive" {
		t.Fatalf("after a restart the mode is %q", m)
	}
	waitFor(t, "alpha sees beta's mode", func() bool {
		for _, d := range a.devices(t) {
			if d.Name == "beta" && d.Mode == "receive" {
				return true
			}
		}
		return false
	})
	for _, d := range b.devices(t) {
		if d.Self && d.Mode != "receive" {
			t.Errorf("beta lists its own mode as %q", d.Mode)
		}
	}

	// A device without a mode file shares.
	a.stop()
	if err := os.Remove(filepath.Join(a.dir, modeFile)); err != nil {
		t.Fatal(err)
	}
	a = restartService(t, &h, a)
	if m := a.status(t).Mode; m != "shared" {
		t.Fatalf("without a mode file the mode is %q, want shared", m)
	}
}

func TestAdminSetsTheMode(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b) // alpha is the root
	waitFor(t, "a connected to b", func() bool { return len(a.status(t).Peers) == 1 })

	if _, err := a.do(t, control.Header{Op: control.OpMode, Device: "beta", Name: "send"}, ""); err != nil {
		t.Fatal(err)
	}
	if m := b.status(t).Mode; m != "send" {
		t.Fatalf("beta's mode is %q, want send", m)
	}
	if _, err := a.do(t, control.Header{Op: control.OpMode, Device: "beta", Name: "everything"}, ""); err == nil {
		t.Error("an unknown mode was sent")
	}
	// A member that is no admin sets only its own mode.
	if _, err := b.do(t, control.Header{Op: control.OpMode, Device: "alpha", Name: "own"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("a member set the root's mode: %v", err)
	}
	if m := a.status(t).Mode; m != "shared" {
		t.Errorf("alpha's mode is %q", m)
	}
	// The root names itself: its own mode changes.
	if _, err := a.do(t, control.Header{Op: control.OpMode, Device: "alpha", Name: "receive"}, ""); err != nil || a.status(t).Mode != "receive" {
		t.Errorf("the root's own mode: %v, %q", err, a.status(t).Mode)
	}
	// alpha may not have seen the connection end yet; then it ends while
	// alpha waits for the result.
	b.stop()
	if _, err := a.do(t, control.Header{Op: control.OpMode, Device: "beta", Name: "own"}, ""); err == nil ||
		!strings.Contains(err.Error(), "not connected") && !strings.Contains(err.Error(), "closed before it answered") {
		t.Errorf("a mode for a device that is off: %v", err)
	}
}

// TestCommandRefused checks the receiving side: a command is carried out
// once, and one for another device or signed by no admin is refused.
func TestCommandRefused(t *testing.T) {
	root, err := group.Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srv := &Service{cfg: Config{StateDir: dir, now: time.Now}, logf: t.Logf, id: root,
		records: group.NewRecords(root.GroupCA.Cert), eng: clip.New(clip.Config{Self: string(root.ID), Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})}
	ca, chain := root.Signer()
	now := time.Now()
	sign := func(to group.DeviceID, mode string, key crypto.Signer) group.Record {
		c, err := group.SignCommand(group.CommandBody{Type: group.CommandMode, Group: group.Tag(root.GroupCA.Cert), By: root.ID, To: to,
			ID: group.NewCommandID(), TimeMS: now.UnixMilli(), ExpiresMS: now.Add(group.CommandLifetime).UnixMilli(), Mode: mode}, key, chain...)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	good := sign(root.ID, "receive", ca.Key)
	if r := srv.command(root.ID, good); r.Status != node.ResultDone || srv.eng.Mode() != clip.Receive {
		t.Fatalf("a good command: %+v, mode %v", r, srv.eng.Mode())
	}
	if m, _ := loadMode(dir); m != clip.Receive {
		t.Errorf("the mode saved is %v", m)
	}
	if r := srv.command(root.ID, good); r.Status != node.ResultRefused || !strings.Contains(r.Reason, "already") {
		t.Errorf("the same command again: %+v", r)
	}
	if r := srv.command(root.ID, sign(group.NewDeviceID(), "own", ca.Key)); r.Status != node.ResultRefused {
		t.Errorf("a command for another device: %+v", r)
	}
	other, _ := group.NewKey()
	if r := srv.command(root.ID, sign(root.ID, "own", other)); r.Status != node.ResultRefused {
		t.Errorf("a command nobody in the group signed: %+v", r)
	}
	if r := srv.command(root.ID, sign(root.ID, "everything", ca.Key)); r.Status != node.ResultRefused || r.ID == "" {
		t.Errorf("an unknown mode: %+v", r)
	}
	if srv.eng.Mode() != clip.Receive {
		t.Errorf("a refused command changed the mode to %v", srv.eng.Mode())
	}
}
