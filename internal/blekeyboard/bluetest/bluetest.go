// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

// Package bluetest plays bluetoothd for the Bluetooth keyboard's tests: a
// private bus with one adapter whose managers read what the keyboard
// registers, as BlueZ does, and a host that subscribes to its keys.
package bluetest

import (
	"bufio"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
)

// The names BlueZ answers to, as blekeyboard calls them.
const (
	bluezBus      = "org.bluez"
	adapterPath   = dbus.ObjectPath("/org/bluez/hci0")
	adapterIface  = "org.bluez.Adapter1"
	gattManager   = "org.bluez.GattManager1"
	advManager    = "org.bluez.LEAdvertisingManager1"
	agentManager  = "org.bluez.AgentManager1"
	charIface     = "org.bluez.GattCharacteristic1"
	advIface      = "org.bluez.LEAdvertisement1"
	objectManager = "org.freedesktop.DBus.ObjectManager"
	propsIface    = "org.freedesktop.DBus.Properties"
)

// Report is the keyboard's input report, under blekeyboard's root.
const Report = dbus.ObjectPath("/tools/cbb/keyboard/hid/report")

// A BlueZ is the fake bluetoothd.
type BlueZ struct {
	Addr string // the private bus's address
	conn *dbus.Conn

	mu           sync.Mutex
	powered      bool
	app          string // the bus name that registered the keyboard
	objects      map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	discoverable []bool
	agents       []string
	pairable     bool
	removed      []dbus.ObjectPath
}

// Start runs a private bus with the fake on it, its adapter powered.
func Start(t testing.TB) *BlueZ {
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
	f := &BlueZ{Addr: strings.TrimSpace(addr), powered: true}
	f.conn = f.Connect(t)
	f.conn.Export(f, "/", objectManager)
	f.conn.Export(adapter{f}, adapterPath, gattManager)
	f.conn.Export(adapter{f}, adapterPath, advManager)
	f.conn.Export(adapter{f}, adapterPath, propsIface)
	f.conn.Export(adapter{f}, adapterPath, adapterIface)
	f.conn.Export(agents{f}, "/org/bluez", agentManager)
	if r, err := f.conn.RequestName(bluezBus, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("taking BlueZ's name: %v %v", r, err)
	}
	return f
}

// Connect opens another connection to the private bus.
func (f *BlueZ) Connect(t testing.TB) *dbus.Conn {
	t.Helper()
	c, err := dbus.Connect(f.Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// SetPowered turns the adapter on or off.
func (f *BlueZ) SetPowered(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.powered = on
}

// Objects are what the keyboard registered: its services,
// characteristics and descriptors.
func (f *BlueZ) Objects() map[dbus.ObjectPath]map[string]map[string]dbus.Variant {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objects
}

// Discoverable is whether each advertisement was, in the order registered.
func (f *BlueZ) Discoverable() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.discoverable)
}

// Agents are the agent calls, in order.
func (f *BlueZ) Agents() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.agents)
}

// Pairable is whether the keyboard made the adapter pairable.
func (f *BlueZ) Pairable() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pairable
}

// Keyboard is the object path on the keyboard's connection, as a host
// reaches it through BlueZ.
func (f *BlueZ) Keyboard(path dbus.ObjectPath) dbus.BusObject {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conn.Object(f.app, path)
}

// Subscribe plays a host that subscribes to the input report: the values
// the keyboard sends come on the channel. Stop ends it.
func (f *BlueZ) Subscribe(t testing.TB) (reports <-chan []byte, stop func()) {
	t.Helper()
	signals := make(chan *dbus.Signal, 256)
	f.conn.Signal(signals)
	if err := f.conn.AddMatchSignal(dbus.WithMatchObjectPath(Report), dbus.WithMatchInterface(propsIface)); err != nil {
		t.Fatal(err)
	}
	out := make(chan []byte, 256)
	go func() {
		for s := range signals {
			if s.Path != Report || len(s.Body) < 2 {
				continue
			}
			if v, ok := s.Body[1].(map[string]dbus.Variant)["Value"].Value().([]byte); ok {
				out <- v
			}
		}
	}()
	if err := f.Keyboard(Report).Call(charIface+".StartNotify", 0).Err; err != nil {
		t.Fatal(err)
	}
	return out, func() { f.Keyboard(Report).Call(charIface+".StopNotify", 0) }
}

func (f *BlueZ) GetManagedObjects() (map[dbus.ObjectPath]map[string]map[string]dbus.Variant, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[dbus.ObjectPath]map[string]map[string]dbus.Variant{
		adapterPath: {
			adapterIface: {"Powered": dbus.MakeVariant(f.powered)},
			gattManager:  {},
			advManager:   {},
		},
	}, nil
}

type adapter struct{ f *BlueZ }

func (a adapter) RegisterApplication(sender dbus.Sender, app dbus.ObjectPath, _ map[string]dbus.Variant) *dbus.Error {
	var objs map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	if err := a.f.conn.Object(string(sender), app).Call(objectManager+".GetManagedObjects", 0).Store(&objs); err != nil {
		return dbus.MakeFailedError(err)
	}
	a.f.mu.Lock()
	a.f.objects, a.f.app = objs, string(sender)
	a.f.mu.Unlock()
	return nil
}

func (a adapter) UnregisterApplication(dbus.ObjectPath) *dbus.Error { return nil }

func (a adapter) RegisterAdvertisement(sender dbus.Sender, adv dbus.ObjectPath, _ map[string]dbus.Variant) *dbus.Error {
	var props map[string]dbus.Variant
	if err := a.f.conn.Object(string(sender), adv).Call(propsIface+".GetAll", 0, advIface).Store(&props); err != nil {
		return dbus.MakeFailedError(err)
	}
	if props["Type"].Value() != "peripheral" || props["Appearance"].Value() != uint16(0x03c1) {
		return dbus.MakeFailedError(errors.New("not a keyboard's advertisement"))
	}
	d, _ := props["Discoverable"].Value().(bool)
	a.f.mu.Lock()
	a.f.discoverable = append(a.f.discoverable, d)
	a.f.mu.Unlock()
	return nil
}

func (a adapter) UnregisterAdvertisement(dbus.ObjectPath) *dbus.Error { return nil }

func (a adapter) RemoveDevice(dev dbus.ObjectPath) *dbus.Error {
	a.f.mu.Lock()
	defer a.f.mu.Unlock()
	a.f.removed = append(a.f.removed, dev)
	return nil
}

// Disconnect says that BlueZ disconnected the device at dev for reason,
// as BlueZ 5.82 and later do.
func (f *BlueZ) Disconnect(dev dbus.ObjectPath, reason string) error {
	return f.conn.Emit(dev, "org.bluez.Device1.Disconnected", reason, "")
}

// Removed lists the devices whose bonds were removed.
func (f *BlueZ) Removed() []dbus.ObjectPath {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dbus.ObjectPath(nil), f.removed...)
}

func (a adapter) Set(iface, name string, v dbus.Variant) *dbus.Error {
	a.f.mu.Lock()
	defer a.f.mu.Unlock()
	if iface == adapterIface && name == "Pairable" {
		a.f.pairable, _ = v.Value().(bool)
	}
	return nil
}

type agents struct{ f *BlueZ }

func (m agents) call(what string) *dbus.Error {
	m.f.mu.Lock()
	defer m.f.mu.Unlock()
	m.f.agents = append(m.f.agents, what)
	return nil
}

func (m agents) RegisterAgent(_ dbus.ObjectPath, capability string) *dbus.Error {
	return m.call("register " + capability)
}
func (m agents) RequestDefaultAgent(dbus.ObjectPath) *dbus.Error { return m.call("default") }
func (m agents) UnregisterAgent(dbus.ObjectPath) *dbus.Error     { return m.call("unregister") }
