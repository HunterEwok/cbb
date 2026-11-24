// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package blekeyboard

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/HunterEwok/cbb/internal/blekeyboard/bluetest"
	"github.com/HunterEwok/cbb/internal/keyboard"
)

func TestKeyboard(t *testing.T) {
	f := bluetest.Start(t)
	if bluetest.Report != root+"/hid/report" {
		t.Fatalf("bluetest's report is %s", bluetest.Report)
	}
	k, err := Open(f.Connect(t), "deck", "", t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	// BlueZ got the HID service with its report map, and a keyboard's
	// advertisement that only bonded hosts see.
	objs := f.Objects()
	if got := objs[root+"/hid"][serviceIface]["UUID"].Value(); got != uuidHID {
		t.Fatalf("the HID service: %v", got)
	}
	if got := objs[root+"/hid/report/ref"][descIface]["UUID"].Value(); got != uuidReportRef {
		t.Fatalf("the input report's reference: %v", got)
	}
	var m []byte
	if err := f.Keyboard(root+"/hid/map").Call(charIface+".ReadValue", 0, map[string]dbus.Variant{}).Store(&m); err != nil || !slices.Equal(m, keyboard.Descriptor) {
		t.Fatalf("the report map: %x %v", m, err)
	}
	if d := f.Discoverable(); !slices.Equal(d, []bool{false}) {
		t.Fatalf("advertisements: %v", d)
	}

	// No host yet.
	if err := k.Type(context.Background(), "hi", keyboard.US, 60); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("typing with no host: %v", err)
	}
	var refusal *Refusal
	if err := k.Type(context.Background(), "\u043f\u0440\u0438", keyboard.US, 60); !errors.As(err, &refusal) || !strings.Contains(err.Error(), "\u043f") {
		t.Fatalf("typing what the layout cannot: %v", err)
	}

	// A host subscribes to the input report and gets the keys of a text.
	reports, stop := f.Subscribe(t)
	if !k.Connected() {
		t.Fatal("not connected after the host subscribed")
	}
	if err := k.Type(context.Background(), "Hi!", keyboard.US, 60); err != nil {
		t.Fatal(err)
	}
	want, _ := keyboard.US.Reports("Hi!")
	for i, w := range want {
		if v := <-reports; !slices.Equal(v, w[:]) {
			t.Fatalf("report %d: %x, want %x", i, v, w)
		}
	}
	stop()
	if k.Connected() {
		t.Fatal("connected after the host left")
	}

	// Visible for a moment: discoverable and pairable, with the agent the
	// default, which takes a pairing then and refuses it after. The test
	// keeps the keyboard's clock and runs its timer.
	var mu sync.Mutex
	clock := time.Unix(1_000_000, 0)
	var hide func()
	k.mu.Lock()
	k.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	k.afterFun = func(d time.Duration, f func()) {
		if d != 300*time.Millisecond {
			t.Errorf("visible for %v", d)
		}
		hide = f
	}
	k.mu.Unlock()
	if err := k.Visible(300 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ag := f.Keyboard(root + "/agent")
	if err := ag.Call(agentIface+".RequestAuthorization", 0, dbus.ObjectPath("/org/bluez/hci0/dev_AA")).Err; err != nil {
		t.Fatalf("a pairing while visible: %v", err)
	}
	mu.Lock()
	clock = clock.Add(300 * time.Millisecond)
	mu.Unlock()
	hide()
	if err := ag.Call(agentIface+".RequestAuthorization", 0, dbus.ObjectPath("/org/bluez/hci0/dev_AA")).Err; err == nil {
		t.Fatal("a pairing was taken after the keyboard stopped being visible")
	}
	if d := f.Discoverable(); !slices.Equal(d, []bool{false, true, false}) || !f.Pairable() {
		t.Fatalf("advertisements %v, pairable %v", d, f.Pairable())
	}
	if a := f.Agents(); !slices.Equal(a, []string{"register NoInputNoOutput", "default", "unregister"}) {
		t.Fatalf("agents: %v", a)
	}
}

func TestPoweredOff(t *testing.T) {
	f := bluetest.Start(t)
	f.SetPowered(false)
	if _, err := Open(f.Connect(t), "deck", "", t.Logf); !errors.Is(err, ErrOff) {
		t.Fatalf("an adapter that is off: %v", err)
	}
}

func TestSettings(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir)
	if err != nil || s != (Settings{Layout: keyboard.US, Rate: DefaultRate}) {
		t.Fatalf("no settings: %+v %v", s, err)
	}
	if err := Save(dir, Settings{On: true, Layout: keyboard.RU, Rate: 1000, Pastes: true}); err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(dir); s != (Settings{On: true, Layout: keyboard.RU, Rate: MaxRate, Pastes: true}) {
		t.Fatalf("saved: %+v", s)
	}
}

// A host that forgot the keyboard loses its old bond here once its
// connection fails authentication; no other device does.
func TestForgetsStaleBond(t *testing.T) {
	f := bluetest.Start(t)
	dir := t.TempDir()
	k, err := Open(f.Connect(t), "deck", dir, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	tv, headphones := dbus.ObjectPath("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01"), dbus.ObjectPath("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02")
	read := f.Keyboard(root+"/hid/report").Call(charIface+".ReadValue", 0, map[string]dbus.Variant{"device": dbus.MakeVariant(tv)})
	if read.Err != nil {
		t.Fatal(read.Err)
	}
	if err := f.Disconnect(headphones, reasonAuth); err != nil {
		t.Fatal(err)
	}
	if err := f.Disconnect(tv, "org.bluez.Reason.Remote"); err != nil {
		t.Fatal(err)
	}
	// Another program on the bus that says the same is not BlueZ. A call
	// on its connection returns once the bus has passed its signal on, so
	// the keyboard has it before BlueZ's own below: had it taken it, the
	// TV's bond would go twice.
	other := f.Connect(t)
	if err := other.Emit(tv, deviceIface+".Disconnected", reasonAuth, ""); err != nil {
		t.Fatal(err)
	}
	if err := other.BusObject().Call("org.freedesktop.DBus.GetId", 0).Err; err != nil {
		t.Fatal(err)
	}
	if err := f.Disconnect(tv, reasonAuth); err != nil {
		t.Fatal(err)
	}
	if got := <-f.Removals(); got != tv {
		t.Fatalf("removed %v, want %s", got, tv)
	}
	k.Close()
	if got := f.Removed(); len(got) != 1 || got[0] != tv {
		t.Fatalf("removed %v, want only %s", got, tv)
	}
	// The hosts are kept: none left once the TV's bond went.
	if hosts := loadHosts(dir); len(hosts) != 0 {
		t.Errorf("hosts kept: %v", hosts)
	}
}
