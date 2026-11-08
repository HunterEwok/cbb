// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/hlc"
	"github.com/HunterEwok/cbb/internal/node"
)

func TestSyncOnOff(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	if _, err := a.do(t, control.Header{Op: control.OpSync, Name: "off"}, ""); err == nil {
		t.Error("a device in no group turned sync off")
	}
	pairWith(t, a, b)
	for _, s := range []*testService{a, b} {
		if m := s.status(t).Mode; m != "shared" {
			t.Fatalf("%s: a new device's mode is %q, want shared (sync on)", s.name, m)
		}
	}
	waitFor(t, "a connected to b", func() bool { return len(a.status(t).Peers) == 1 })

	if _, err := b.do(t, control.Header{Op: control.OpSync, Name: "own"}, ""); err == nil {
		t.Error("sync took a mode's name")
	}
	m, err := b.do(t, control.Header{Op: control.OpSync, Name: "off"}, "")
	if err != nil || m.Status.Mode != "own" || m.Status.SyncUntilMS != 0 {
		t.Fatalf("sync off: %v, %+v", err, m)
	}
	// A deliberate copy reaches the group with sync off, and cbb paste on
	// the other device prints the group's text.
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "from beta"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has beta's text", func() bool { return a.paste(t) == "from beta" })
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from alpha"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta prints the group's text", func() bool { return b.paste(t) == "from alpha" })

	// Sync off is saved, and the others see it in the hello after a restart.
	b.stop()
	b = restartService(t, &h, b)
	if m := b.status(t).Mode; m != "own" {
		t.Fatalf("after a restart the mode is %q", m)
	}
	waitFor(t, "alpha sees beta's sync off", func() bool {
		for _, d := range a.devices(t) {
			if d.Name == "beta" && d.Mode == "own" {
				return true
			}
		}
		return false
	})
	for _, d := range b.devices(t) {
		if d.Self && d.Mode != "own" {
			t.Errorf("beta lists its own mode as %q", d.Mode)
		}
	}

	// Off for a while: the status says until when, and sync on removes the file.
	m, err = b.do(t, control.Header{Op: control.OpSync, Name: "off", ForMS: time.Hour.Milliseconds()}, "")
	if err != nil || m.Status.SyncUntilMS == 0 {
		t.Fatalf("sync off for an hour: %v, %+v", err, m)
	}
	if _, err := b.do(t, control.Header{Op: control.OpSync, Name: "off", ForMS: 31 * 24 * time.Hour.Milliseconds()}, ""); err == nil {
		t.Error("sync off for 31 days was taken")
	}
	if m, err := b.do(t, control.Header{Op: control.OpSync, Name: "on"}, ""); err != nil || m.Status.Mode != "shared" {
		t.Fatalf("sync on: %v, %+v", err, m)
	}
	if _, err := os.Stat(filepath.Join(b.dir, syncFile)); !os.IsNotExist(err) {
		t.Errorf("sync on left %s: %v", syncFile, err)
	}
}

// TestSyncOffForAWhileTurnsOn restarts a device whose time off passed
// meanwhile: sync is on again.
func TestSyncOffForAWhileTurnsOn(t *testing.T) {
	dir := t.TempDir()
	e := clip.New(clip.Config{Self: "a", Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})
	e.SetSync(false, time.Now().Add(-time.Minute))
	data := fmt.Sprintf(`{"off":true,"until_ms":%d}`, time.Now().Add(-time.Minute).UnixMilli())
	if err := os.WriteFile(filepath.Join(dir, syncFile), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	f := clip.New(clip.Config{Self: "a", Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})
	if err := loadSync(dir, f); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.Sync(); !on {
		t.Error("sync off whose time passed is still off")
	}
	if on, _ := e.Sync(); !on {
		t.Error("the engine kept sync off past its time")
	}
}

func TestAdminTurnsSync(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b) // alpha is the root
	waitFor(t, "a connected to b", func() bool { return len(a.status(t).Peers) == 1 })

	if _, err := a.do(t, control.Header{Op: control.OpSync, Device: "beta", Name: "off"}, ""); err != nil {
		t.Fatal(err)
	}
	if m := b.status(t).Mode; m != "own" {
		t.Fatalf("beta's mode is %q, want own", m)
	}
	if _, err := a.do(t, control.Header{Op: control.OpSync, Device: "beta", Name: "off", ForMS: 1000}, ""); err == nil {
		t.Error("an admin turned another device's sync off for a while")
	}
	// A member that is no admin turns only its own sync.
	if _, err := b.do(t, control.Header{Op: control.OpSync, Device: "alpha", Name: "off"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("a member turned the root's sync off: %v", err)
	}
	if m := a.status(t).Mode; m != "shared" {
		t.Errorf("alpha's mode is %q", m)
	}
	// The root names itself: its own sync changes.
	if _, err := a.do(t, control.Header{Op: control.OpSync, Device: "alpha", Name: "off"}, ""); err != nil || a.status(t).Mode != "own" {
		t.Errorf("the root's own sync: %v, %q", err, a.status(t).Mode)
	}
	// alpha may not have seen the connection end yet; then it ends while
	// alpha waits for the result.
	b.stop()
	if _, err := a.do(t, control.Header{Op: control.OpSync, Device: "beta", Name: "on"}, ""); err == nil ||
		!strings.Contains(err.Error(), "not connected") && !strings.Contains(err.Error(), "closed before it answered") {
		t.Errorf("sync on for a device that is off: %v", err)
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
	good := sign(root.ID, "own", ca.Key)
	if r := srv.command(root.ID, good); r.Status != node.ResultDone || srv.eng.Mode() != clip.Own {
		t.Fatalf("a good command: %+v, mode %v", r, srv.eng.Mode())
	}
	saved := clip.New(clip.Config{Self: string(root.ID), Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})
	if err := loadSync(dir, saved); err != nil || saved.Mode() != clip.Own {
		t.Errorf("the sync saved: %v, %v", saved.Mode(), err)
	}
	if r := srv.command(root.ID, good); r.Status != node.ResultRefused || !strings.Contains(r.Reason, "already") {
		t.Errorf("the same command again: %+v", r)
	}
	if r := srv.command(root.ID, sign(group.NewDeviceID(), "shared", ca.Key)); r.Status != node.ResultRefused {
		t.Errorf("a command for another device: %+v", r)
	}
	other, _ := group.NewKey()
	if r := srv.command(root.ID, sign(root.ID, "shared", other)); r.Status != node.ResultRefused {
		t.Errorf("a command nobody in the group signed: %+v", r)
	}
	for _, mode := range []string{"everything", "receive", "send"} {
		if r := srv.command(root.ID, sign(root.ID, mode, ca.Key)); r.Status != node.ResultRefused || r.ID == "" {
			t.Errorf("an unknown mode %q: %+v", mode, r)
		}
	}
	if srv.eng.Mode() != clip.Own {
		t.Errorf("a refused command changed the mode to %v", srv.eng.Mode())
	}
}
