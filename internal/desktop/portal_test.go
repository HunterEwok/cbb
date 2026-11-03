// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/ei"
	"github.com/HunterEwok/cbb/internal/ei/eitest"
)

// fakePortal plays xdg-desktop-portal's RemoteDesktop on a private bus,
// with an EIS server for each session.
type fakePortal struct {
	t    *testing.T
	conn *dbus.Conn

	mu       sync.Mutex
	decline  bool          // the user says no in the dialog
	answer   time.Duration // how long the user takes in the dialog
	restored []string      // the restore tokens the client brought
	servers  []*eitest.Server
}

func (f *fakePortal) respond(sender dbus.Sender, opts map[string]dbus.Variant, code uint32, results map[string]dbus.Variant, after time.Duration) dbus.ObjectPath {
	tok, _ := opts["handle_token"].Value().(string)
	name := strings.ReplaceAll(strings.TrimPrefix(string(sender), ":"), ".", "_")
	path := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/portal/desktop/request/%s/%s", name, tok))
	go func() {
		time.Sleep(after)
		f.conn.Emit(path, portalRequest+".Response", code, results)
	}()
	return path
}

func (f *fakePortal) CreateSession(sender dbus.Sender, opts map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	return f.respond(sender, opts, 0, map[string]dbus.Variant{"session_handle": dbus.MakeVariant("/org/freedesktop/portal/desktop/session/1")}, 0), nil
}

func (f *fakePortal) SelectDevices(sender dbus.Sender, session dbus.ObjectPath, opts map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	if types, _ := opts["types"].Value().(uint32); types != portalKeyboard {
		f.t.Errorf("SelectDevices asked for devices %d", types)
	}
	f.mu.Lock()
	if t, ok := opts["restore_token"].Value().(string); ok {
		f.restored = append(f.restored, t)
	}
	f.mu.Unlock()
	return f.respond(sender, opts, 0, map[string]dbus.Variant{}, 0), nil
}

func (f *fakePortal) Start(sender dbus.Sender, session dbus.ObjectPath, parent string, opts map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	decline, answer := f.decline, f.answer
	f.mu.Unlock()
	if decline {
		return f.respond(sender, opts, 1, map[string]dbus.Variant{}, answer), nil
	}
	return f.respond(sender, opts, 0, map[string]dbus.Variant{"devices": dbus.MakeVariant(portalKeyboard),
		"restore_token": dbus.MakeVariant("restore-1")}, answer), nil
}

func (f *fakePortal) ConnectToEIS(session dbus.ObjectPath, opts map[string]dbus.Variant) (dbus.UnixFD, *dbus.Error) {
	s, fd, err := eitest.New()
	if err != nil {
		return 0, dbus.MakeFailedError(err)
	}
	f.mu.Lock()
	f.servers = append(f.servers, s)
	f.mu.Unlock()
	return dbus.UnixFD(fd), nil
}

// server is the EIS server of the latest session.
func (f *fakePortal) server() *eitest.Server {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.servers) == 0 {
		return nil
	}
	return f.servers[len(f.servers)-1]
}

// startPortal runs a private bus with a fake portal on it and returns the
// bus's address.
func startPortal(t *testing.T, version uint32) (*fakePortal, string) {
	t.Helper()
	addr := startBus(t)
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	f := &fakePortal{t: t, conn: conn}
	if err := conn.Export(f, portalPath, portalRemote); err != nil {
		t.Fatal(err)
	}
	if _, err := prop.Export(conn, portalPath, prop.Map{portalRemote: {"version": {Value: version}}}); err != nil {
		t.Fatal(err)
	}
	if r, err := conn.RequestName(portalBus, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("taking the portal's name: %v %v", r, err)
	}
	return f, addr
}

// startBus runs a private session bus and returns its address.
func startBus(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("no dbus-daemon")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address=1", "--address=unix:dir="+t.TempDir())
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(addr)
}

func openPortal(t *testing.T, addr string) *portal {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	p := portalOn(conn, t.Logf)
	if p == nil {
		conn.Close()
		return nil
	}
	t.Cleanup(p.close)
	return p
}

func wantKeys(t *testing.T, s *eitest.Server, want []eitest.Key) {
	t.Helper()
	for _, w := range want {
		select {
		case k := <-s.Keys:
			if k != w {
				t.Fatalf("the EIS server got %+v, want %+v", k, w)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("the EIS server got no key, want %+v", w)
		}
	}
}

// TestPortal checks the RemoteDesktop session: the first paste starts it,
// the keys reach the compositor's EIS server, and the restore token the
// portal gives is kept and brought to the next session.
func TestPortal(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	f, addr := startPortal(t, 2)
	p := openPortal(t, addr)
	if p == nil {
		t.Fatal("no portal at version 2")
	}
	if err := p.ready(); err != nil {
		t.Fatal(err)
	}
	if err := p.press([]ei.Key{{Code: ei.KeyLeftShift, Press: true}, {Code: ei.KeyInsert, Press: true}, {Code: ei.KeyInsert}, {Code: ei.KeyLeftShift}}); err != nil {
		t.Fatal(err)
	}
	wantKeys(t, f.server(), []eitest.Key{{Code: ei.KeyLeftShift, Press: true}, {Code: ei.KeyInsert, Press: true}, {Code: ei.KeyInsert}, {Code: ei.KeyLeftShift}})
	dir, _ := stateDir()
	if b, err := os.ReadFile(filepath.Join(dir, portalTokenFile)); err != nil || strings.TrimSpace(string(b)) != "restore-1" {
		t.Errorf("the kept restore token: %q, %v", b, err)
	}

	// The compositor ends the session: the next paste starts a new one,
	// with the token, so the user is not asked again.
	f.server().Close()
	var err error
	for range 50 {
		if err = p.press([]ei.Key{{Code: ei.KeyEnter, Press: true}, {Code: ei.KeyEnter}}); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err == nil {
		t.Fatal("keys went to a session that ended")
	}
	if err := p.ready(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	restored := f.restored
	f.mu.Unlock()
	if len(restored) != 1 || restored[0] != "restore-1" {
		t.Errorf("the restore tokens brought: %q", restored)
	}
	if err := p.press([]ei.Key{{Code: ei.KeyEnter, Press: true}, {Code: ei.KeyEnter}}); err != nil {
		t.Fatal(err)
	}
	wantKeys(t, f.server(), []eitest.Key{{Code: ei.KeyEnter, Press: true}, {Code: ei.KeyEnter}})
}

// TestPortalDialog checks the answers in the portal's dialog: while the
// user has not answered, a paste is refused so that the sender pastes
// again; once they declined, every paste is refused.
func TestPortalDialog(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	f, addr := startPortal(t, 2)
	f.mu.Lock()
	f.decline, f.answer = true, 3*portalAnswer
	f.mu.Unlock()
	p := openPortal(t, addr)
	var r *connector.Refusal
	start := time.Now()
	if err := p.ready(); !errors.As(err, &r) || !strings.Contains(r.Reason, "paste again") {
		t.Fatalf("a paste while the dialog is open: %v", err)
	}
	if d := time.Since(start); d > portalAnswer+time.Second {
		t.Errorf("the paste waited %v for the dialog", d)
	}
	// A paste meanwhile waits for the same dialog, it opens no second one.
	if err := p.ready(); !errors.As(err, &r) || !strings.Contains(r.Reason, "paste again") {
		t.Fatalf("a second paste while the dialog is open: %v", err)
	}
	time.Sleep(2 * portalAnswer)
	if err := p.ready(); !errors.As(err, &r) || !strings.Contains(r.Reason, "declined") {
		t.Fatalf("a paste after the user declined: %v", err)
	}
	f.mu.Lock()
	n := len(f.servers)
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("%d EIS connections after the user declined", n)
	}
}

// TestPortalVersion checks that a portal older than version 2, which has
// no ConnectToEIS, is not used.
func TestPortalVersion(t *testing.T) {
	_, addr := startPortal(t, 1)
	if p := openPortal(t, addr); p != nil {
		t.Error("a portal at version 1 is used")
	}
}
