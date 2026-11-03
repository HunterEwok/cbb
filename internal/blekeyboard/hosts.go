// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package blekeyboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	"github.com/godbus/dbus/v5"

	"github.com/HunterEwok/cbb/internal/atomicfile"
)

// A host that forgot the keyboard (reset, or "Forget" on its side) cannot
// pair again while BlueZ keeps the old bond here: BlueZ starts encryption
// with the old key, the host answers that it has none, and the connection
// drops each time. So the keyboard remembers the hosts that read its
// characteristics (BlueZ names the device in a read's options), and when
// one of them is disconnected for failed authentication, it forgets that
// bond, and the host can pair again. Only those hosts: never another of
// the computer's own Bluetooth devices. BlueZ says why a device was
// disconnected from 5.82; with an older BlueZ the user removes the bond
// (bluetoothctl remove ADDRESS).

const (
	hostsFile    = "keyboard-hosts"
	deviceIface  = "org.bluez.Device1"
	reasonAuth   = "org.bluez.Reason.Authentication"
	maxKeptHosts = 16
)

// loadHosts reads the hosts kept in dir.
func loadHosts(dir string) []dbus.ObjectPath {
	if dir == "" {
		return nil
	}
	var hosts []dbus.ObjectPath
	if b, err := os.ReadFile(filepath.Join(dir, hostsFile)); err == nil {
		json.Unmarshal(b, &hosts) // a broken file starts over
	}
	return hosts
}

// sawHost remembers the device that read a characteristic, from the
// options of the read.
func (k *Keyboard) sawHost(opts map[string]dbus.Variant) {
	p, ok := opts["device"].Value().(dbus.ObjectPath)
	if !ok || !p.IsValid() {
		return
	}
	k.mu.Lock()
	if slices.Contains(k.hosts, p) {
		k.mu.Unlock()
		return
	}
	k.hosts = append(k.hosts, p)
	if len(k.hosts) > maxKeptHosts {
		k.hosts = k.hosts[len(k.hosts)-maxKeptHosts:]
	}
	hosts := slices.Clone(k.hosts)
	k.mu.Unlock()
	k.saveHosts(hosts)
}

func (k *Keyboard) saveHosts(hosts []dbus.ObjectPath) {
	if k.dir == "" {
		return
	}
	b, err := json.Marshal(hosts)
	if err == nil {
		err = atomicfile.Write(filepath.Join(k.dir, hostsFile), b, 0o600)
	}
	if err != nil {
		k.logf("cbb: keyboard: keeping its hosts: %v", err)
	}
}

// watchDisconnects forgets the bond of a host whose connection failed
// authentication, until the keyboard closes.
func (k *Keyboard) watchDisconnects() {
	match := []dbus.MatchOption{dbus.WithMatchInterface(deviceIface), dbus.WithMatchMember("Disconnected")}
	if err := k.conn.AddMatchSignal(match...); err != nil {
		k.logf("cbb: keyboard: watching for hosts that forgot it: %v", err)
		return
	}
	ch := make(chan *dbus.Signal, 8)
	k.conn.Signal(ch)
	k.stopWatch = func() {
		k.conn.RemoveSignal(ch)
		k.conn.RemoveMatchSignal(match...)
		close(ch)
	}
	go func() {
		for sig := range ch {
			if sig.Name != deviceIface+".Disconnected" || len(sig.Body) == 0 {
				continue
			}
			if reason, _ := sig.Body[0].(string); reason == reasonAuth {
				k.forgetHost(sig.Path)
			}
		}
	}()
}

// forgetHost removes the bond with the device at p, when it is one of the
// keyboard's hosts.
func (k *Keyboard) forgetHost(p dbus.ObjectPath) {
	k.mu.Lock()
	i := slices.Index(k.hosts, p)
	if i < 0 {
		k.mu.Unlock()
		return
	}
	k.hosts = slices.Delete(k.hosts, i, i+1)
	hosts := slices.Clone(k.hosts)
	k.mu.Unlock()
	k.saveHosts(hosts)
	name := string(p)
	if v, err := k.conn.Object(bluezBus, p).GetProperty(deviceIface + ".Alias"); err == nil {
		if s, ok := v.Value().(string); ok {
			name = s
		}
	}
	if err := k.conn.Object(bluezBus, k.adapter).Call(adapterIface+".RemoveDevice", 0, p).Err; err != nil {
		k.logf("cbb: keyboard: %s has forgotten this keyboard, and its old pairing could not be removed here: %v", name, err)
		return
	}
	k.logf("cbb: keyboard: %s had forgotten this keyboard; its old pairing is gone here too, so it can pair again (cbb keyboard pair)", name)
}
